
v_cc_library(
  NAME features
  SRCS
    feature_table.cc
    logger.cc
  DEPS
    Seastar::seastar
    v::model
  )
add_subdirectory(tests)
