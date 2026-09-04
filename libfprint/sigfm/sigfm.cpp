// SIGFM algorithm for libfprint

// Copyright (C) 2022 Matthieu CHARETTE <matthieu.charette@gmail.com>
// Copyright (c) 2022 Natasha England-Elbro <natasha@natashaee.me>
// Copyright (c) 2022 Timur Mangliev <tigrmango@gmail.com>
//
// SPDX-License-Identifier: LGPL-2.1-or-later
//

#include "sigfm.h"
#include "binary.hpp"
#include "img-info.hpp"

#include "opencv2/core/persistence.hpp"
#include "opencv2/core/types.hpp"
#include "opencv2/features2d.hpp"
#include <algorithm>
#include <array>
#include <climits>
#include <cstdlib>
#include <cstring>
#include <iterator>
#include <memory>
#include <set>
#include <string>
#include <tuple>
#include <utility>

#include <vector>

namespace bin {

template<>
struct serializer<SigfmImgInfo> : public std::true_type {
    static void serialize(const SigfmImgInfo& info, stream& out)
    {
        if (info.descriptors.rows != static_cast<int>(info.keypoints.size()))
            throw std::runtime_error{"keypoint and descriptor counts differ"};
        out << info.keypoints << info.descriptors;
    }
};

template<>
struct deserializer<SigfmImgInfo> : public std::true_type {
    static SigfmImgInfo deserialize(stream& in)
    {
        SigfmImgInfo info;
        in >> info.keypoints >> info.descriptors;
        if (info.descriptors.rows != static_cast<int>(info.keypoints.size()))
            throw std::runtime_error{"keypoint and descriptor counts differ"};
        return info;
    }
};
} // namespace bin

namespace {
constexpr auto distance_match = 0.75;
constexpr auto length_match = 0.05;
constexpr auto angle_match = 0.05;
constexpr auto min_match = 5;
constexpr auto max_matches = std::size_t{176};
constexpr auto max_angles = std::size_t{500};
struct match {
    cv::Point2i p1;
    cv::Point2i p2;
    bool operator<(const match& right) const
    {
        return std::tie(this->p1.y, this->p1.x, this->p2.y, this->p2.x) <
               std::tie(right.p1.y, right.p1.x, right.p2.y, right.p2.x);
    }
};
struct angle {
    double cos;
    double sin;
};
} // namespace

SigfmImgInfo* sigfm_copy_info(SigfmImgInfo* info) { return new SigfmImgInfo{*info}; }

int sigfm_keypoints_count(SigfmImgInfo* info) { return info->keypoints.size(); }

namespace {
constexpr unsigned char sigfm_blob_magic[4] = {'S', 'G', 'F', 'M'};
constexpr unsigned char sigfm_blob_version_legacy = 1;
constexpr unsigned char sigfm_blob_version = 2;
constexpr std::size_t sigfm_keypoint_size = 7 * sizeof(guint32);
constexpr std::size_t sigfm_blob_max_size =
    5 + sizeof(guint64) + bin::MAX_KEYPOINTS * sigfm_keypoint_size +
    3 * sizeof(guint32) +
    bin::MAX_KEYPOINTS * bin::SIFT_DESCRIPTOR_COLS * sizeof(float);

enum class legacy_byte_order {
    little,
    big,
};

template<typename T>
T read_legacy_value(bin::stream& in, legacy_byte_order order)
{
    alignas(T) std::array<bin::byte, sizeof(T)> bytes{};
    in.read(bytes.begin(), bytes.size());
#if G_BYTE_ORDER == G_LITTLE_ENDIAN
    if (order == legacy_byte_order::big)
#else
    if (order == legacy_byte_order::little)
#endif
        std::reverse(bytes.begin(), bytes.end());

    T value;
    std::memcpy(&value, bytes.data(), sizeof(value));
    return value;
}

template<typename Size>
SigfmImgInfo deserialize_legacy_v1(bin::stream& in, legacy_byte_order order)
{
    const auto count = read_legacy_value<Size>(in, order);
    if (count > bin::MAX_KEYPOINTS || count > in.size())
        throw std::runtime_error{"invalid legacy keypoint count"};

    SigfmImgInfo info;
    info.keypoints.reserve(static_cast<std::size_t>(count));
    for (Size index = 0; index < count; index++) {
        cv::KeyPoint point;
        point.class_id = read_legacy_value<int>(in, order);
        point.angle = read_legacy_value<float>(in, order);
        point.octave = read_legacy_value<int>(in, order);
        point.response = read_legacy_value<float>(in, order);
        point.size = read_legacy_value<float>(in, order);
        point.pt.x = read_legacy_value<float>(in, order);
        point.pt.y = read_legacy_value<float>(in, order);
        info.keypoints.emplace_back(std::move(point));
    }

    const auto type = read_legacy_value<gint32>(in, order);
    const auto rows = read_legacy_value<gint32>(in, order);
    const auto cols = read_legacy_value<gint32>(in, order);
    if (rows == 0) {
        if (!((type == 0 && cols == 0) ||
              (type == CV_32F && cols == bin::SIFT_DESCRIPTOR_COLS)))
            throw std::runtime_error{"invalid legacy empty descriptor matrix"};
    } else {
        if (rows < 0 || rows > static_cast<gint32>(bin::MAX_KEYPOINTS) ||
            cols != bin::SIFT_DESCRIPTOR_COLS || type != CV_32F ||
            static_cast<std::size_t>(rows) * cols * sizeof(float) > in.size())
            throw std::runtime_error{"invalid legacy descriptor matrix"};

        info.descriptors.create(rows, cols, type);
        for (gint32 row = 0; row < rows; row++)
            for (gint32 col = 0; col < cols; col++)
                info.descriptors.at<float>(row, col) =
                    read_legacy_value<float>(in, order);
    }

    if (info.descriptors.rows != static_cast<int>(info.keypoints.size()))
        throw std::runtime_error{"legacy keypoint and descriptor counts differ"};
    return info;
}

template<typename Size>
std::unique_ptr<SigfmImgInfo>
try_deserialize_legacy_v1(const unsigned char* begin, const unsigned char* end,
                          legacy_byte_order order)
{
    try {
        bin::stream in{begin, end};
        auto info = std::make_unique<SigfmImgInfo>(
            deserialize_legacy_v1<Size>(in, order));
        if (in.size() != 0)
            return nullptr;
        return info;
    } catch (const std::exception&) {
        return nullptr;
    }
}
} // namespace

unsigned char* sigfm_serialize_binary(SigfmImgInfo* info, int* outlen)
{
    if (!outlen)
        return nullptr;

    *outlen = 0;
    try {
        if (!info)
            return nullptr;

        bin::stream s;
        s << *info;
        if (s.size() > static_cast<std::size_t>(INT_MAX - 5))
            return nullptr;

        const auto payload = static_cast<int>(s.size());
        auto* out = static_cast<unsigned char*>(std::malloc(payload + 5));
        if (!out)
            return nullptr;

        std::memcpy(out, sigfm_blob_magic, 4);
        out[4] = sigfm_blob_version;
        std::memcpy(out + 5, s.data(), payload);
        *outlen = payload + 5;
        return out;
    } catch (const std::exception&) {
        return nullptr;
    }
}

SigfmImgInfo* sigfm_deserialize_binary(const unsigned char* bytes, int len)
{
    try {
        if (!bytes || len < 5 ||
            static_cast<std::size_t>(len) > sigfm_blob_max_size ||
            std::memcmp(bytes, sigfm_blob_magic, 4) != 0)
            return nullptr;

        if (bytes[4] == sigfm_blob_version_legacy) {
            auto info = try_deserialize_legacy_v1<guint64>(
                bytes + 5, bytes + len, legacy_byte_order::little);
            if (!info)
                info = try_deserialize_legacy_v1<guint32>(
                    bytes + 5, bytes + len, legacy_byte_order::little);
            if (!info)
                info = try_deserialize_legacy_v1<guint64>(
                    bytes + 5, bytes + len, legacy_byte_order::big);
            if (!info)
                info = try_deserialize_legacy_v1<guint32>(
                    bytes + 5, bytes + len, legacy_byte_order::big);
            return info.release();
        }
        if (bytes[4] != sigfm_blob_version)
            return nullptr;

        bin::stream s{bytes + 5, bytes + len};
        auto info = std::make_unique<SigfmImgInfo>();
        s >> *info;
        if (s.size() != 0)
            return nullptr;
        return info.release();
    }
    catch (const std::exception&) {
        return nullptr;
    }
}

SigfmImgInfo* sigfm_extract(const SigfmPix* pix, int width, int height)
{
    try {
        cv::Mat img;
        img.create(height, width, CV_8UC1);
        std::memcpy(img.data, pix, width * height);
        const auto roi = cv::Mat::ones(cv::Size{img.size[1], img.size[0]}, CV_8UC1);
        std::vector<cv::KeyPoint> pts;

        cv::Mat descs;
        cv::SIFT::create(static_cast<int>(bin::MAX_KEYPOINTS))
            ->detectAndCompute(img, roi, pts, descs);

        auto* info = new SigfmImgInfo{pts, descs};
        return info;
    } catch(...) {
        return nullptr;
    }
}

int sigfm_match_score(SigfmImgInfo* frame, SigfmImgInfo* enrolled)
{
    try {
        if (frame->descriptors.empty() || enrolled->descriptors.empty())
            return 0;

        std::vector<std::vector<cv::DMatch>> points;
        auto bfm = cv::BFMatcher::create();
        bfm->knnMatch(frame->descriptors, enrolled->descriptors, points, 2);
        std::set<match> matches_unique;
        std::vector<std::pair<float, match>> candidates;
        int nb_matched = 0;
        for (const auto& pts : points) {
            if (pts.size() < 2) {
                continue;
            }
            const cv::DMatch& match_1 = pts.at(0);
            if (match_1.distance < distance_match * pts.at(1).distance) {
                match m{frame->keypoints.at(match_1.queryIdx).pt,
                        enrolled->keypoints.at(match_1.trainIdx).pt};
                if (matches_unique.insert(m).second)
                    candidates.emplace_back(match_1.distance, m);
                nb_matched++;
            }
        }
        if (nb_matched < min_match) {
            return 0;
        }
        /* stable_sort, not sort: a self-match produces many candidates tied
         * at distance 0, and which of them survives the 176-cap below must
         * not depend on the stdlib's unstable-sort tie order -- that would
         * make the score non-reproducible across implementations. */
        std::stable_sort(candidates.begin(), candidates.end(),
                         [](const auto& a, const auto& b) { return a.first < b.first; });
        if (candidates.size() > max_matches)
            candidates.resize(max_matches);
        std::vector<match> matches;
        matches.reserve(candidates.size());
        for (const auto& c : candidates)
            matches.push_back(c.second);

        std::vector<angle> angles;
        for (std::size_t j = 0; j < matches.size(); j++) {
            if (angles.size() >= max_angles)
                break;

            const auto& match_1 = matches[j];
            for (std::size_t k = j + 1; k < matches.size(); k++) {
                const auto& match_2 = matches[k];

                int vec_1[2] = {match_1.p1.x - match_2.p1.x,
                                match_1.p1.y - match_2.p1.y};
                int vec_2[2] = {match_1.p2.x - match_2.p2.x,
                                match_1.p2.y - match_2.p2.y};

                double length_1 = sqrt(pow(vec_1[0], 2) + pow(vec_1[1], 2));
                double length_2 = sqrt(pow(vec_2[0], 2) + pow(vec_2[1], 2));

                if (1 - std::min(length_1, length_2) /
                            std::max(length_1, length_2) <=
                    length_match) {

                    double product = length_1 * length_2;
                    angles.push_back({
                        M_PI / 2 +
                            asin((vec_1[0] * vec_2[0] + vec_1[1] * vec_2[1]) /
                                 product),
                        acos((vec_1[0] * vec_2[1] - vec_1[1] * vec_2[0]) /
                             product),
                    });
                }

                if (angles.size() >= max_angles)
                    break;
            }
        }

        if (angles.size() < min_match) {
            return 0;
        }

        int count = 0;
        for (std::size_t j = 0; j < angles.size(); j++) {
            const auto& angle_1 = angles[j];
            for (std::size_t k = j + 1; k < angles.size(); k++) {
                const auto& angle_2 = angles[k];

                if (1 - std::min(angle_1.sin, angle_2.sin) /
                                std::max(angle_1.sin, angle_2.sin) <=
                        angle_match &&
                    1 - std::min(angle_1.cos, angle_2.cos) /
                                std::max(angle_1.cos, angle_2.cos) <=
                        angle_match) {

                    count += 1;
                }
            }
        }
        return count;
    }
    catch (...) {
        return -1;
    }
}

void sigfm_free_info(SigfmImgInfo* info) { delete info; }
