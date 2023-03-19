#ifndef HEADER_HPP
#define HEADER_HPP

#ifdef _WIN32
#include <Windows.h>
#include <io.h>
#define F_OK 0
#define access _access
#endif

#ifdef __APPLE__
#include <unistd.h>
#include <filesystem>
#include <curl/curl.h>
#include </usr/local/Cellar/jsoncpp/1.9.5/include/json/json.h>
#include </usr/local/Cellar/jsoncpp/1.9.5/include/json/reader.h>
// #include </usr/local/Cellar/spdlog/1.11.0/include/spdlog/spdlog.h>

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
#include <algorithm>
#include <sstream>

#endif