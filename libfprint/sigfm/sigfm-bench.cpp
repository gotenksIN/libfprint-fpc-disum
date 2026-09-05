/*
 * SIGFM 1:N matching benchmark
 * Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

/*
 * Measures FAR/FRR of the shipped SIGFM implementation by calling the same
 * public entry points a driver does -- sigfm_extract() and sigfm_match_score()
 * -- rather than a reimplementation of the algorithm.
 *
 * A large-area reference print is reduced to a sequence of small windows that
 * approximate what a small-area sensor sees: a random placement (offset plus
 * rotation) of the finger over the capture window, optionally upscaled the way
 * a driver does before extraction. Each subject contributes a gallery of
 * `--stages` windows (standing in for a multi-stage enrolment) and `--probes`
 * further windows used as verification attempts. A probe is scored against the
 * whole gallery, taking the best score, which is what fpi_print_sigfm_match()
 * does.
 *
 * Output is a CSV of `is_genuine,score` compatible with wl2776's
 * plot_sigfm_evaluations.py (https://gitlab.com/wl2776/sigfm-eval).
 *
 * Input images are binary PGM (P5, maxval 255), one subject per file, named
 * so that the subject id is the text before the first underscore -- the
 * FVC/NIST convention, e.g. `101_1.pgm`, `101_2.pgm`, `102_1.pgm`. Convert a
 * dataset with ImageMagick:
 *
 *     mogrify -format pgm -compress none *.tif
 */

#include "sigfm.h"

#include <algorithm>
#include <cctype>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dirent.h>
#include <fstream>
#include <map>
#include <random>
#include <string>
#include <vector>

namespace {

struct Image {
    int w = 0, h = 0;
    std::vector<unsigned char> px;
    bool valid() const { return w > 0 && h > 0; }
    unsigned char at(int x, int y) const
    {
        return px[static_cast<size_t>(y) * w + x];
    }
};

Image read_pgm(const std::string& path)
{
    Image im;
    std::ifstream f(path, std::ios::binary);

    if (!f)
        return im;

    std::string magic;
    f >> magic;
    if (magic != "P5")
        return {};

    auto next_int = [&f]() {
        int v = -1;
        while (f) {
            int c = f.peek();
            if (c == '#') {
                std::string line;
                std::getline(f, line);
                continue;
            }
            if (std::isspace(c)) {
                f.get();
                continue;
            }
            f >> v;
            break;
        }
        return v;
    };

    int w = next_int(), h = next_int(), maxv = next_int();
    if (w <= 0 || h <= 0 || maxv != 255)
        return {};
    f.get();

    im.w = w;
    im.h = h;
    im.px.resize(static_cast<size_t>(w) * h);
    f.read(reinterpret_cast<char*>(im.px.data()),
           static_cast<std::streamsize>(w) * h);
    if (!f)
        return {};
    return im;
}

/* One placement of the finger over the capture window: rotate about the
 * requested centre and sample a w*h window, then replicate each pixel `scale`
 * times as the fpc1022 driver does before handing the image to SIGFM. */
Image sample_window(const Image& src, double cx, double cy, double theta, int w,
                    int h, int scale)
{
    Image out;

    out.w = w * scale;
    out.h = h * scale;
    out.px.assign(static_cast<size_t>(out.w) * out.h, 255);

    const double ct = std::cos(theta), st = std::sin(theta);

    for (int j = 0; j < out.h; j++) {
        for (int i = 0; i < out.w; i++) {
            /* Undo the upscale, then map into the source frame. */
            const double lx = (i / scale) - w / 2.0;
            const double ly = (j / scale) - h / 2.0;
            const double sx = cx + lx * ct - ly * st;
            const double sy = cy + lx * st + ly * ct;
            const int ix = static_cast<int>(std::lround(sx));
            const int iy = static_cast<int>(std::lround(sy));

            if (ix >= 0 && ix < src.w && iy >= 0 && iy < src.h)
                out.px[static_cast<size_t>(j) * out.w + i] = src.at(ix, iy);
        }
    }
    return out;
}

struct Opts {
    std::string dir;
    std::string out = "sigfm-bench.csv";
    int width = 112, height = 88, scale = 2;
    int stages = 5, probes = 5;
    int max_subjects = 0;    /* 0 = all */
    double max_shift = 0.25; /* fraction of the window */
    double max_rot_deg = 25.0;
    unsigned seed = 12345;
    int threshold = 10;
};

std::string subject_of(const std::string& fname)
{
    const auto us = fname.find('_');

    return us == std::string::npos ? fname : fname.substr(0, us);
}

struct Sample {
    SigfmImgInfo* info = nullptr;
    std::string subject;
};

void usage(const char* argv0)
{
    std::fprintf(
        stderr,
        "usage: %s -i <dir-of-pgm> [options]\n"
        "  -o <file>       output CSV (default sigfm-bench.csv)\n"
        "  -W <px> -H <px> capture window (default 112x88)\n"
        "  --scale <n>     driver upscale factor (default 2)\n"
        "  --stages <n>    gallery windows per subject (default 5)\n"
        "  --probes <n>    probe windows per subject (default 5)\n"
        "  --subjects <n>  limit number of subjects\n"
        "  --rot <deg>     max random rotation (default 25)\n"
        "  --shift <frac>  max random shift, fraction of window (default "
        "0.25)\n"
        "  --threshold <n> score threshold for the summary (default 10)\n"
        "  --seed <n>      RNG seed (default 12345)\n",
        argv0);
}

} // namespace

int main(int argc, char** argv)
{
    Opts o;

    for (int i = 1; i < argc; i++) {
        const std::string a = argv[i];
        auto need = [&](const char* what) {
            if (i + 1 >= argc) {
                std::fprintf(stderr, "%s needs a value\n", what);
                std::exit(2);
            }
            return std::string(argv[++i]);
        };

        if (a == "-i")
            o.dir = need("-i");
        else if (a == "-o")
            o.out = need("-o");
        else if (a == "-W")
            o.width = std::stoi(need("-W"));
        else if (a == "-H")
            o.height = std::stoi(need("-H"));
        else if (a == "--scale")
            o.scale = std::stoi(need("--scale"));
        else if (a == "--stages")
            o.stages = std::stoi(need("--stages"));
        else if (a == "--probes")
            o.probes = std::stoi(need("--probes"));
        else if (a == "--subjects")
            o.max_subjects = std::stoi(need("--subjects"));
        else if (a == "--rot")
            o.max_rot_deg = std::stod(need("--rot"));
        else if (a == "--shift")
            o.max_shift = std::stod(need("--shift"));
        else if (a == "--threshold")
            o.threshold = std::stoi(need("--threshold"));
        else if (a == "--seed")
            o.seed = std::stoul(need("--seed"));
        else {
            usage(argv[0]);
            return 2;
        }
    }

    if (o.dir.empty()) {
        usage(argv[0]);
        return 2;
    }

    /* Collect one representative file per subject. */
    std::map<std::string, std::string> by_subject;
    if (DIR* d = opendir(o.dir.c_str())) {
        while (dirent* e = readdir(d)) {
            const std::string n = e->d_name;
            if (n.size() < 5 || n.compare(n.size() - 4, 4, ".pgm") != 0)
                continue;
            by_subject.emplace(subject_of(n), o.dir + "/" + n);
        }
        closedir(d);
    }
    else {
        std::fprintf(stderr, "cannot open %s\n", o.dir.c_str());
        return 1;
    }

    if (by_subject.empty()) {
        std::fprintf(stderr, "no .pgm files in %s\n", o.dir.c_str());
        return 1;
    }

    std::mt19937 rng(o.seed);
    std::vector<std::vector<Sample>> galleries;
    std::vector<Sample> probes;
    int subjects = 0;

    for (const auto& kv : by_subject) {
        if (o.max_subjects && subjects >= o.max_subjects)
            break;

        const Image full = read_pgm(kv.second);
        if (!full.valid()) {
            std::fprintf(stderr, "skip (unreadable) %s\n", kv.second.c_str());
            continue;
        }
        if (full.w < o.width || full.h < o.height) {
            std::fprintf(stderr, "skip (too small) %s\n", kv.second.c_str());
            continue;
        }

        const double sx = o.width * o.max_shift, sy = o.height * o.max_shift;
        std::uniform_real_distribution<double> dx(-sx, sx), dy(-sy, sy);
        std::uniform_real_distribution<double> dr(-o.max_rot_deg * M_PI / 180.0,
                                                  o.max_rot_deg * M_PI / 180.0);

        auto make = [&]() {
            const Image win = sample_window(full, full.w / 2.0 + dx(rng),
                                            full.h / 2.0 + dy(rng), dr(rng),
                                            o.width, o.height, o.scale);
            return sigfm_extract(win.px.data(), win.w, win.h);
        };

        std::vector<Sample> gal;
        for (int i = 0; i < o.stages; i++)
            if (SigfmImgInfo* info = make())
                gal.push_back({info, kv.first});

        /* A gallery that could not be built is an enrolment failure, not a
         * matching result; drop the subject rather than bias the scores. */
        if (static_cast<int>(gal.size()) < o.stages) {
            for (auto& s : gal)
                sigfm_free_info(s.info);
            std::fprintf(stderr, "skip (enrolment failed) %s\n",
                         kv.second.c_str());
            continue;
        }

        for (int i = 0; i < o.probes; i++)
            if (SigfmImgInfo* info = make())
                probes.push_back({info, kv.first});

        galleries.push_back(std::move(gal));
        subjects++;
        std::fprintf(stderr, "\renrolled %d subjects", subjects);
    }
    std::fprintf(stderr, "\n");

    if (galleries.empty() || probes.empty()) {
        std::fprintf(stderr, "nothing to compare\n");
        return 1;
    }

    std::FILE* csv = std::fopen(o.out.c_str(), "w");
    if (!csv) {
        std::fprintf(stderr, "cannot write %s\n", o.out.c_str());
        return 1;
    }
    std::fprintf(csv, "is_genuine,score\n");

    long genuine_n = 0, genuine_hit = 0, impostor_n = 0, impostor_hit = 0;
    long long cmp_count = 0;

    for (const auto& p : probes) {
        for (const auto& gal : galleries) {
            /* Best score across the gallery, as fpi_print_sigfm_match does. */
            int best = 0;
            for (const auto& g : gal) {
                const int s = sigfm_match_score(g.info, p.info);
                cmp_count++;
                if (s > best)
                    best = s;
            }

            const bool genuine = (gal.front().subject == p.subject);
            std::fprintf(csv, "%d,%d\n", genuine ? 1 : 0, best);

            if (genuine) {
                genuine_n++;
                if (best >= o.threshold)
                    genuine_hit++;
            }
            else {
                impostor_n++;
                if (best >= o.threshold)
                    impostor_hit++;
            }
        }
        std::fprintf(stderr, "\r%lld comparisons", cmp_count);
    }
    std::fprintf(stderr, "\n");
    std::fclose(csv);

    std::printf("subjects            : %d\n", subjects);
    std::printf("window              : %dx%d (upscaled x%d)\n", o.width,
                o.height, o.scale);
    std::printf("gallery/probes      : %d/%d per subject\n", o.stages,
                o.probes);
    std::printf("score comparisons   : %lld\n", cmp_count);
    std::printf("threshold           : %d\n", o.threshold);
    std::printf("genuine attempts    : %ld\n", genuine_n);
    std::printf("impostor attempts   : %ld\n", impostor_n);
    if (genuine_n)
        std::printf("TAR                 : %.4f  (FRR %.4f)\n",
                    double(genuine_hit) / genuine_n,
                    1.0 - double(genuine_hit) / genuine_n);
    if (impostor_n)
        std::printf("FAR                 : %.6f  (%ld/%ld)\n",
                    double(impostor_hit) / impostor_n, impostor_hit,
                    impostor_n);
    std::printf("csv                 : %s\n", o.out.c_str());

    for (auto& gal : galleries)
        for (auto& s : gal)
            sigfm_free_info(s.info);
    for (auto& p : probes)
        sigfm_free_info(p.info);

    return 0;
}
