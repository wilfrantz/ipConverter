#ifndef HEADER_HPP
#define HEADER_HPP

#ifdef _WIN32
#include <Windows.h>
#include <io.h>
#define F_OK 0
#define access _access
#endif

#ifdef __APPLE__

#else

#include <unistd.h>
#include <spdlog/spdlog.h>
#include <jsoncpp/json/json.h>
#include <jsoncpp/json/reader.h>

#include <iostream>
#include <filesystem>
#include <curl/curl.h>
#include <bits/stdc++.h>

#endif
#include <string>
#include <vector>
#include <fstream>
#include <sstream>
#include <unistd.h>
#include <iostream>
#include <algorithm>
#include <filesystem>
#include <curl/curl.h>
#include <json/json.h>
#include <json/reader.h>
#include <boost/asio.hpp>
#include <spdlog/spdlog.h>

#endif