# Makefile.am for traffic/iocore/io_uring
#
#  Licensed to the Apache Software Foundation (ASF) under one
#  or more contributor license agreements.  See the NOTICE file
#  distributed with this work for additional information
#  regarding copyright ownership.  The ASF licenses this file
#  to you under the Apache License, Version 2.0 (the
#  "License"); you may not use this file except in compliance
#  with the License.  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

AM_CPPFLAGS += \
	-I$(abs_top_srcdir)/iocore/eventsystem \
	-I$(abs_top_srcdir)/include \
	-I$(abs_top_srcdir)/lib \
	$(TS_INCLUDES)

noinst_LIBRARIES = libinkuring.a

libinkuring_a_SOURCES = \
	io_uring.cc \
	I_IO_URING.h \
	P_IO_URING.h
