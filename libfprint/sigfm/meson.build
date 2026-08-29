
sigfm_sources = ['sigfm.cpp']

opencv = opencv_dep
have_sigfm = have_opencv

if have_sigfm
  libsigfm = static_library('sigfm',
          sigfm_sources,
          dependencies: [opencv],
          cpp_args: cpp.get_supported_arguments([
              '-Wno-suggest-attribute=format',
          ]),
  )

  doctest = dependency('doctest', required: false)
  if doctest.found()
    sigfm_tests = executable('sigfm-tests', ['./tests.cpp'], dependencies: [doctest, opencv], link_with: [libsigfm])
  endif

  # FAR/FRR benchmark over a fingerprint dataset. Not installed and not run as
  # part of the test suite: it needs a dataset that cannot be shipped here.
  sigfm_bench = executable('sigfm-bench', ['./sigfm-bench.cpp'],
          dependencies: [opencv],
          link_with: [libsigfm],
          build_by_default: false,
          install: false,
  )
endif
