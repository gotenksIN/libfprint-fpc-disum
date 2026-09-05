// SIGFM algorithm for libfprint

// Copyright (C) 2022 Matthieu CHARETTE <matthieu.charette@gmail.com>
// Copyright (c) 2022 Natasha England-Elbro <natasha@natashaee.me>
// Copyright (c) 2022 Timur Mangliev <tigrmango@gmail.com>
//
// SPDX-License-Identifier: LGPL-2.1-or-later
//

#pragma once

#include <glib.h>
#include "opencv2/core/mat.hpp"
#include <algorithm>
#include <array>
#include <cstring>
#include <stdexcept>
#include <type_traits>
#include <vector>

namespace bin {
using byte = unsigned char;

constexpr std::size_t MAX_KEYPOINTS = 2048;
constexpr int SIFT_DESCRIPTOR_COLS = 128;

class stream;

template<typename T, typename EnableIf = void>
struct serializer : public std::false_type {
    void serialize(const T& m, stream& out);
};

template<typename T, typename EnableIf = void>
struct deserializer : public std::false_type {
    T deserialize(stream& in);
};
class stream {
public:
    stream() = default;

    template<
        typename Iter,
        std::enable_if_t<std::is_same_v<typename std::iterator_traits<
                                            std::decay_t<Iter>>::value_type,
                                        byte>,
                         bool> = true>
    stream(Iter begin, Iter end) : store_{begin, end}
    {
    }

    template<typename T, std::enable_if_t<serializer<T>::value, bool> = true>
    constexpr stream& operator<<(T v)
    {
        serializer<T>::serialize(v, *this);
        return *this;
    }

    template<typename T, std::enable_if_t<deserializer<T>::value, bool> = true>
    constexpr stream& operator>>(T& v)
    {
        v = deserializer<T>::deserialize(*this);
        return *this;
    }

    template<
        typename Iter,
        std::enable_if_t<std::is_same_v<typename std::iterator_traits<
                                            std::decay_t<Iter>>::value_type,
                                        byte>,
                         bool> = true>
    constexpr stream& write(Iter&& begin, Iter&& end)
    {
        std::copy(std::forward<Iter>(begin), std::forward<Iter>(end),
                  std::back_inserter(store_));
        return *this;
    }

    template<
        typename Iter,
        std::enable_if_t<std::is_same_v<typename std::iterator_traits<
                                            std::decay_t<Iter>>::value_type,
                                        byte>,
                         bool> = true>
    constexpr stream& read(Iter&& begin, std::size_t dist)
    {
        if (dist > size()) {
            throw std::runtime_error{"trying to read too much from a stream. wanted: " + std::to_string(dist) + " available: " + std::to_string(size())};
        }
        std::copy(store_.begin() + read_offset_,
                  store_.begin() + read_offset_ + dist, begin);
        read_offset_ += dist;
        return *this;
    }
    const byte* data() const { return store_.data() + read_offset_; }
    std::size_t size() const { return store_.size() - read_offset_; }

private:
    std::vector<byte> store_;
    std::size_t read_offset_ = 0;
};

template<typename T>
struct serializer<T, std::enable_if_t<std::is_arithmetic_v<T>>> : public std::true_type {
    static void serialize(T v, stream& out) {
        using seg_store = std::array<byte, sizeof(T)>;
        alignas(T) seg_store s = {};
        std::memcpy(s.data(), &v, sizeof(T));
#if G_BYTE_ORDER == G_BIG_ENDIAN
        std::reverse(s.begin(), s.end());
#endif
        out.write(s.begin(), s.end());
    }
};


template<typename T>
struct deserializer<T, std::enable_if_t<std::is_arithmetic_v<T>>> : public std::true_type {
    static T deserialize(stream& in) {
        alignas(T) std::array<byte, sizeof(T)> s = {};
        in.read(s.begin(), s.size());
#if G_BYTE_ORDER == G_BIG_ENDIAN
        std::reverse(s.begin(), s.end());
#endif
        T v;
        std::memcpy(&v, s.data(), s.size());
        return v;
    }
};


template<>
struct serializer<cv::Mat> : public std::true_type {
    static void serialize(const cv::Mat& m, stream& out)
    {
        if (!m.empty() &&
            (m.type() != CV_32F || m.cols != SIFT_DESCRIPTOR_COLS ||
             m.rows > static_cast<int>(MAX_KEYPOINTS))) {
            throw std::runtime_error{"invalid descriptor matrix"};
        }

        const auto type = static_cast<guint32>(m.empty() ? CV_32F : m.type());
        const auto rows = static_cast<guint32>(m.rows);
        const auto cols = static_cast<guint32>(m.empty() ? SIFT_DESCRIPTOR_COLS : m.cols);

        out << type << rows << cols;
        for (int row = 0; row < m.rows; row++)
            for (int col = 0; col < m.cols; col++)
                out << m.at<float>(row, col);
    }
};

template<>
struct deserializer<cv::Mat> : public std::true_type {
    static cv::Mat deserialize(stream& in)
    {
        guint32 rows, cols, type;
        in >> type >> rows >> cols;

        if (rows == 0) {
            if (type != CV_32F || cols != SIFT_DESCRIPTOR_COLS) {
                throw std::runtime_error{"invalid empty descriptor matrix"};
            }
            return {};
        }

        if (rows > MAX_KEYPOINTS || cols != SIFT_DESCRIPTOR_COLS ||
            type != CV_32F ||
            static_cast<std::size_t>(rows) * cols * sizeof(float) > in.size()) {
            throw std::runtime_error{"invalid descriptor matrix"};
        }

        cv::Mat m;
        m.create(rows, cols, type);
        for (guint32 row = 0; row < rows; row++)
            for (guint32 col = 0; col < cols; col++)
                in >> m.at<float>(row, col);
        return m;
    }
};

template<typename T>
struct deserializer<cv::Point_<T>> : public std::true_type {
    static cv::Point2f deserialize(stream& in)
    {
        cv::Point_<T> p;
        in >> p.x >> p.y;
        return p;
    }
};
template<typename T>
struct serializer<cv::Point_<T>> : public std::true_type {
    static void serialize(const cv::Point_<T>& pt, stream& out)
    {
        out << pt.x << pt.y;
    }
};

template<>
struct serializer<cv::KeyPoint> : public std::true_type {
    static void serialize(const cv::KeyPoint& pt, stream& out)
    {
        out << pt.class_id << pt.angle << pt.octave << pt.response << pt.size
            << pt.pt;
    }
};

template<>
struct deserializer<cv::KeyPoint> : public std::true_type {
    static cv::KeyPoint deserialize(stream& in)
    {
        cv::KeyPoint pt;
        in >> pt.class_id >> pt.angle >> pt.octave >> pt.response >> pt.size >>
            pt.pt;
        return pt;
    }
};


template<typename T>
struct serializer<std::vector<T>, std::enable_if_t<serializer<T>::value>> : public std::true_type {
    static void serialize(const std::vector<T>& vs, stream& out)
    {
        if (vs.size() > MAX_KEYPOINTS) {
            throw std::runtime_error{"invalid vector size"};
        }
        out << static_cast<guint32>(vs.size());
        std::for_each(vs.begin(), vs.end(),
                      [&out](const auto& el) { out << el; });
    }
};

template<typename T>
struct deserializer<std::vector<T>, std::enable_if_t<deserializer<T>::value>> : public std::true_type {
    static std::vector<T> deserialize(stream& in)
    {
        guint32 size;
        in >> size;
        if (size > MAX_KEYPOINTS || size > in.size()) {
            throw std::runtime_error{"invalid vector size"};
        }
        std::vector<T> vs;
        vs.reserve(size);
        for (std::size_t n = 0; n != size; ++n) {
            T v;
            in >> v;
            vs.emplace_back(std::move(v));
        }
        return vs;
    }
};
} // namespace bin
