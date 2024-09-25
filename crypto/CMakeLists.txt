
add_library(lokinet-libntrup
  STATIC
  libntrup/src/ntru.cpp
  libntrup/src/ref/randomsmall.c
  libntrup/src/ref/swap.c
  libntrup/src/ref/rq_round3.c
  libntrup/src/ref/rq_recip3.c
  libntrup/src/ref/small.c
  libntrup/src/ref/rq_mult.c
  libntrup/src/ref/randomweightw.c
  libntrup/src/ref/random32.c
  libntrup/src/ref/dec.c
  libntrup/src/ref/r3_mult.c
  libntrup/src/ref/r3_recip.c
  libntrup/src/ref/keypair.c
  libntrup/src/ref/rq_rounded.c
  libntrup/src/ref/enc.c
  libntrup/src/ref/int32_sort.c
  libntrup/src/ref/rq.c
)

target_include_directories(lokinet-libntrup PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/libntrup/include)

# The avx implementation uses runtime CPU feature detection to enable itself, so we *always* want to
# compile it with avx2/fma support when supported by the compiler even if we aren't compiling with
# general AVX2 enabled.
set(NTRU_AVX_SRC
  libntrup/src/avx/randomsmall.c
  libntrup/src/avx/weight.c
  libntrup/src/avx/swap.c
  libntrup/src/avx/rq_round3.c
  libntrup/src/avx/rq_recip3.c
  libntrup/src/avx/small.c
  libntrup/src/avx/randomweightw.c
  libntrup/src/avx/dec.c
  libntrup/src/avx/r3_recip.c
  libntrup/src/avx/keypair.c
  libntrup/src/avx/rq_rounded.c
  libntrup/src/avx/mult.c
  libntrup/src/avx/enc.c
  libntrup/src/avx/int32_sort.c
  libntrup/src/avx/rq.c
  libntrup/src/avx/rq_mod3.c
)

include(CheckCXXCompilerFlag)
check_cxx_compiler_flag(-mavx2 COMPILER_SUPPORTS_AVX2)
check_cxx_compiler_flag(-mfma COMPILER_SUPPORTS_FMA)
if(COMPILER_SUPPORTS_AVX2 AND COMPILER_SUPPORTS_FMA AND (NOT ANDROID))
  target_sources(lokinet-libntrup PRIVATE ${NTRU_AVX_SRC})
  set_property(SOURCE ${NTRU_AVX_SRC} APPEND PROPERTY COMPILE_FLAGS "-mavx2 -mfma")
  message(STATUS "Building libntrup with runtime AVX2/FMA support")
else()
  target_sources(lokinet-libntrup PRIVATE libntrup/src/noavx-stubs.c)
  message(STATUS "Not building with libntrup runtime AVX2/FMA support (either this architecture doesn't support them, or your compile doesn't support the -mavx2 -mfma flags")
endif()

enable_lto(lokinet-libntrup)

if (WARNINGS_AS_ERRORS)
  target_compile_options(lokinet-libntrup PUBLIC -Wall -Wextra -Werror)
endif()

target_link_libraries(lokinet-libntrup PUBLIC sodium)

