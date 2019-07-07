cmake_minimum_required(VERSION 2.6)

find_package(DynamoRIO)

include(dynamorio/make/policies.cmake NO_POLICY_SCOPE)

add_library(gluttony SHARED
    gluttony.c
  )

configure_DynamoRIO_client(gluttony)
use_DynamoRIO_extension(gluttony drcontainers)
use_DynamoRIO_extension(gluttony drmgr)
