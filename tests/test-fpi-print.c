/*
 * FpPrint match function unit tests
 * Copyright (c) 2026 Sergey Subbotin <ssubbotin@gmail.com>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <libfprint/fprint.h>
#include "fpi-print.h"
#include "fp-print-private.h"
#ifdef HAVE_SIGFM
#include "sigfm/sigfm.h"
#endif

static FpPrint *
make_print (FpiPrintType type)
{
  /* fp_print_constructed() asserts driver/device-id are set; a bare
   * g_object_new (FP_TYPE_PRINT, NULL) aborts before we get to exercise
   * the match functions, so set both construct-only properties here
   * instead of going through fp_print_new(), which needs a live device. */
  FpPrint *print = g_object_new (FP_TYPE_PRINT,
                                 "driver", "test_driver",
                                 "device-id", "test_device",
                                 NULL);

  g_object_ref_sink (print);
  fpi_print_set_type (print, type);
  return print;
}

#ifdef HAVE_SIGFM
typedef struct
{
  int x;
  int y;
  int r;
} TestDisc;

/* SIFT keys on scale-space blobs, so an all-zero buffer extracts to an empty
 * descriptor set and any two such prints would compare equal for trivial
 * reasons. Painting discs gives the extractor something to describe. */
static guchar *
paint_discs (const TestDisc *discs,
             gsize           n_discs,
             int             size)
{
  guchar *pix = g_malloc0 (size * size);

  for (gsize i = 0; i < n_discs; i++)
    for (int y = 0; y < size; y++)
      for (int x = 0; x < size; x++)
        {
          int dx = x - discs[i].x;
          int dy = y - discs[i].y;

          if (dx * dx + dy * dy <= discs[i].r * discs[i].r)
            pix[y * size + x] = 0xff;
        }

  return pix;
}

static const TestDisc discs_a[] = {
  { 16, 16, 6 }, { 48, 20, 5 }, { 20, 46, 7 }, { 44, 48, 4 }, { 32, 32, 3 },
};

static const TestDisc discs_b[] = {
  { 12, 40, 5 }, { 40, 12, 6 }, { 52, 52, 4 }, { 24, 24, 7 },
};

static FpPrint *
make_sigfm_print (const TestDisc *discs,
                  gsize           n_discs)
{
  FpPrint *print = make_print (FPI_PRINT_SIGFM);

  g_autofree guchar *pix = paint_discs (discs, n_discs, 64);
  SigfmImgInfo *info = sigfm_extract (pix, 64, 64);

  g_assert_nonnull (info);
  g_assert_cmpint (sigfm_keypoints_count (info), >, 0);
  g_ptr_array_add (print->prints, info);
  return print;
}
#endif

static void
test_print_equal_sigfm_same_descriptors (void)
{
#ifdef HAVE_SIGFM
  g_autoptr(FpPrint) a = make_sigfm_print (discs_a, G_N_ELEMENTS (discs_a));
  g_autoptr(FpPrint) b = make_sigfm_print (discs_a, G_N_ELEMENTS (discs_a));

  /* Two separately extracted, structurally distinct infos with the same
   * content: fp_print_equal has to compare the descriptors, not the
   * pointers. */
  g_assert_true (g_ptr_array_index (a->prints, 0) !=
                 g_ptr_array_index (b->prints, 0));
  g_assert_true (fp_print_equal (a, b));
#else
  g_test_skip ("SIGFM not built");
#endif
}

static void
test_print_equal_sigfm_different_descriptors (void)
{
#ifdef HAVE_SIGFM
  g_autoptr(FpPrint) a = make_sigfm_print (discs_a, G_N_ELEMENTS (discs_a));
  g_autoptr(FpPrint) b = make_sigfm_print (discs_b, G_N_ELEMENTS (discs_b));

  g_assert_false (fp_print_equal (a, b));
#else
  g_test_skip ("SIGFM not built");
#endif
}

static void
test_print_equal_sigfm_vs_nbis (void)
{
#ifdef HAVE_SIGFM
  g_autoptr(FpPrint) sigfm = make_sigfm_print (discs_a, G_N_ELEMENTS (discs_a));
  g_autoptr(FpPrint) nbis = make_print (FPI_PRINT_NBIS);

  g_ptr_array_add (nbis->prints, g_new0 (struct xyt_struct, 1));

  /* Must be rejected on the type alone, in both directions: the SIGFM print
   * holds a SigfmImgInfo * where the NBIS branch would read an
   * xyt_struct *. */
  g_assert_false (fp_print_equal (sigfm, nbis));
  g_assert_false (fp_print_equal (nbis, sigfm));
#else
  g_test_skip ("SIGFM not built");
#endif
}

static void
test_bz3_match_rejects_wrong_probe_type (void)
{
#ifdef HAVE_SIGFM
  g_autoptr(FpPrint) template = make_print (FPI_PRINT_NBIS);
  g_autoptr(FpPrint) probe = make_print (FPI_PRINT_SIGFM);
  g_autoptr(GError) error = NULL;
  g_autofree guchar *pix = g_malloc0 (64 * 64);

  /* Give the wrong-typed probe exactly one real print, so the bz3
   * cardinality check (len != 1) cannot mask the type check we are
   * actually testing here. */
  g_ptr_array_add (probe->prints, sigfm_extract (pix, 64, 64));

  g_assert_cmpint (fpi_print_bz3_match (template, probe, 40, &error),
                   ==, FPI_MATCH_ERROR);
  g_assert_nonnull (error);
#else
  g_test_skip ("SIGFM not built");
#endif
}

static void
test_sigfm_match_rejects_wrong_probe_type (void)
{
#ifdef HAVE_SIGFM
  g_autoptr(FpPrint) template = make_print (FPI_PRINT_SIGFM);
  g_autoptr(FpPrint) probe = make_print (FPI_PRINT_NBIS);
  g_autoptr(GError) error = NULL;

  g_assert_cmpint (fpi_print_sigfm_match (template, probe, 10, &error),
                   ==, FPI_MATCH_ERROR);
  g_assert_nonnull (error);
#else
  g_test_skip ("SIGFM not built");
#endif
}

static void
test_sigfm_match_rejects_empty_probe (void)
{
#ifdef HAVE_SIGFM
  g_autoptr(FpPrint) template = make_print (FPI_PRINT_SIGFM);
  g_autoptr(FpPrint) probe = make_print (FPI_PRINT_SIGFM);
  g_autoptr(GError) error = NULL;

  /* probe->prints exists but is empty: must error, not index [0] */
  g_assert_cmpint (fpi_print_sigfm_match (template, probe, 10, &error),
                   ==, FPI_MATCH_ERROR);
  g_assert_nonnull (error);
#else
  g_test_skip ("SIGFM not built");
#endif
}

static void
test_sigfm_blob_roundtrip_and_magic (void)
{
#ifdef HAVE_SIGFM
  /* A flat image yields an info with zero keypoints — still serializable. */
  g_autofree guchar *pix = g_malloc0 (64 * 64);
  SigfmImgInfo *info = sigfm_extract (pix, 64, 64);
  int len = 0;
  unsigned char *blob;
  SigfmImgInfo *back;

  g_assert_nonnull (info);
  blob = sigfm_serialize_binary (info, &len);
  g_assert_cmpint (len, >, 5);
  g_assert_cmpmem (blob, 4, "SGFM", 4);
  g_assert_cmpint (blob[4], ==, 1);

  back = sigfm_deserialize_binary (blob, len);
  g_assert_nonnull (back);
  sigfm_free_info (back);

  /* Corrupt magic: must be rejected. */
  blob[0] = 'X';
  g_assert_null (sigfm_deserialize_binary (blob, len));
  /* Unknown version: must be rejected. */
  blob[0] = 'S';
  blob[4] = 99;
  g_assert_null (sigfm_deserialize_binary (blob, len));
  /* Truncated header: must be rejected. */
  g_assert_null (sigfm_deserialize_binary (blob, 3));

  free (blob);
  sigfm_free_info (info);
#else
  g_test_skip ("SIGFM not built");
#endif
}

int
main (int argc, char *argv[])
{
  g_test_init (&argc, &argv, NULL);
  g_test_add_func ("/print/equal/sigfm_same_descriptors",
                   test_print_equal_sigfm_same_descriptors);
  g_test_add_func ("/print/equal/sigfm_different_descriptors",
                   test_print_equal_sigfm_different_descriptors);
  g_test_add_func ("/print/equal/sigfm_vs_nbis",
                   test_print_equal_sigfm_vs_nbis);
  g_test_add_func ("/print/bz3/rejects_wrong_probe_type",
                   test_bz3_match_rejects_wrong_probe_type);
  g_test_add_func ("/print/sigfm/rejects_wrong_probe_type",
                   test_sigfm_match_rejects_wrong_probe_type);
  g_test_add_func ("/print/sigfm/rejects_empty_probe",
                   test_sigfm_match_rejects_empty_probe);
  g_test_add_func ("/print/sigfm/blob_magic",
                   test_sigfm_blob_roundtrip_and_magic);
  return g_test_run ();
}
