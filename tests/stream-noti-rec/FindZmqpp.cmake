
find_path(LIBZMQPP_INCLUDE_DIR zmqpp/zmqpp.hpp)

find_library(LIBZMQPP_LIBRARY 
    PATHS /usr/lib/x86_64-linux-gnu
    NAMES zmqpp)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(ZMQPP DEFAULT_MSG
                                  LIBZMQPP_LIBRARY LIBZMQPP_INCLUDE_DIR)
mark_as_advanced(LIBZMQPP_INCLUDE_DIR LIBZMQPP_LIBRARY )
set(ZMQPP_LIBRARIES ${LIBZMQPP_LIBRARY} )
set(ZMQPP_INCLUDE_DIRS ${LIBZMQPP_INCLUDE_DIR} )