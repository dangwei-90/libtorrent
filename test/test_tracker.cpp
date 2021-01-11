/*

Copyright (c) 2011-2020, Arvid Norberg
Copyright (c) 2015, Mikhail Titov
Copyright (c) 2016, terry zhao
Copyright (c) 2016-2018, Alden Torres
Copyright (c) 2017-2018, Steven Siloti
Copyright (c) 2018, d-komarov
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions
are met:

    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in
      the documentation and/or other materials provided with the distribution.
    * Neither the name of the author nor the names of its
      contributors may be used to endorse or promote products derived
      from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.

*/

#include "test.hpp"
#include "setup_transfer.hpp"  // for supports_ipv6
#include "test_utils.hpp"
#include "udp_tracker.hpp"
#include "settings.hpp"
#include "libtorrent/alert.hpp"
#include "libtorrent/peer_info.hpp" // for peer_list_entry
#include "libtorrent/alert_types.hpp"
#include "libtorrent/session.hpp"
#include "libtorrent/session_params.hpp"
#include "libtorrent/error_code.hpp"
#include "libtorrent/tracker_manager.hpp"
#include "libtorrent/http_tracker_connection.hpp" // for parse_tracker_response
#include "libtorrent/torrent_info.hpp"
#include "libtorrent/announce_entry.hpp"
#include "libtorrent/torrent.hpp"
#include "libtorrent/aux_/path.hpp"
#include "libtorrent/socket_io.hpp"

#include <iostream>
#include <cstring>
#include <stdio.h>

#ifdef _WIN32
#include <io.h>
#include <tchar.h>
#include <direct.h>
#else
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#endif
#include <stdio.h>

#ifdef _WIN32
#include <Windows.h>
#include <wininet.h>
#include <string>
#pragma comment(lib, "wininet.lib")
#define BUF_SIZE 2048
#else
#include <unistd.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <string.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdlib.h>
#define BUFSIZE 0xF000
#endif

using namespace lt;
using lt::add_torrent_params;
using lt::storage_mode_t;
using namespace std::placeholders;

// TODO: test scrape requests
// TODO: test parse peers6
// TODO: test parse tracker-id
// TODO: test parse failure-reason
// TODO: test all failure paths, including
//   invalid bencoding
//   not a dictionary
//   no files entry in scrape response
//   no info-hash entry in scrape response
//   malformed peers in peer list of dictionaries
//   uneven number of bytes in peers and peers6 string responses

TORRENT_TEST(parse_hostname_peers)
{
	char const response[] = "d5:peersld7:peer id20:aaaaaaaaaaaaaaaaaaaa"
		"2:ip13:test_hostname4:porti1000eed"
		"7:peer id20:bbbbabaababababababa2:ip12:another_host4:porti1001eeee";
	error_code ec;
	tracker_response resp = parse_tracker_response(response
		, ec, {}, sha1_hash());

	TEST_EQUAL(ec, error_code());
	TEST_EQUAL(resp.peers.size(), 2);
	if (resp.peers.size() == 2)
	{
		peer_entry const& e0 = resp.peers[0];
		peer_entry const& e1 = resp.peers[1];
		TEST_EQUAL(e0.hostname, "test_hostname");
		TEST_EQUAL(e0.port, 1000);
		TEST_EQUAL(e0.pid, peer_id("aaaaaaaaaaaaaaaaaaaa"));

		TEST_EQUAL(e1.hostname, "another_host");
		TEST_EQUAL(e1.port, 1001);
		TEST_EQUAL(e1.pid, peer_id("bbbbabaababababababa"));
	}
}

TORRENT_TEST(parse_peers4)
{
	char const response[] = "d5:peers12:\x01\x02\x03\x04\x30\x10"
		"\x09\x08\x07\x06\x20\x10" "e";
	error_code ec;
	tracker_response resp = parse_tracker_response(response
		, ec, {}, sha1_hash());

	TEST_EQUAL(ec, error_code());
	TEST_EQUAL(resp.peers4.size(), 2);
	if (resp.peers.size() == 2)
	{
		ipv4_peer_entry const& e0 = resp.peers4[0];
		ipv4_peer_entry const& e1 = resp.peers4[1];
		TEST_CHECK(e0.ip == addr4("1.2.3.4").to_bytes());
		TEST_EQUAL(e0.port, 0x3010);

		TEST_CHECK(e1.ip == addr4("9.8.7.6").to_bytes());
		TEST_EQUAL(e1.port, 0x2010);
	}
}

#if TORRENT_USE_I2P
TORRENT_TEST(parse_i2p_peers)
{
	// d8:completei8e10:incompletei4e8:intervali3600e5:peers352: ...
	std::uint8_t const response[] = { 0x64, 0x38, 0x3a, 0x63, 0x6f, 0x6d,
		0x70, 0x6c, 0x65, 0x74, 0x65, 0x69, 0x38, 0x65, 0x31, 0x30,
		0x3a, 0x69, 0x6e, 0x63, 0x6f, 0x6d, 0x70, 0x6c, 0x65, 0x74,
		0x65, 0x69, 0x34, 0x65, 0x38, 0x3a, 0x69, 0x6e, 0x74, 0x65,
		0x72, 0x76, 0x61, 0x6c, 0x69, 0x33, 0x36, 0x30, 0x30, 0x65,
		0x35, 0x3a, 0x70, 0x65, 0x65, 0x72, 0x73, 0x33, 0x35, 0x32,
		0x3a, 0xb1, 0x84, 0xe0, 0x96, 0x1f, 0xdb, 0xf2, 0xc9, 0xb0,
		0x53, 0x9a, 0x31, 0xa5, 0x35, 0xcd, 0xe8, 0x59, 0xa0, 0x7c,
		0xcd, 0xf2, 0x7c, 0x81, 0x81, 0x02, 0x11, 0x7b, 0xb4, 0x2a,
		0xd1, 0x20, 0x87, 0xd6, 0x1b, 0x06, 0x4c, 0xbb, 0x4c, 0x4e,
		0x30, 0xf9, 0xa3, 0x5d, 0x58, 0xa0, 0xa5, 0x10, 0x48, 0xfa,
		0x9b, 0x3b, 0x10, 0x86, 0x43, 0x5c, 0x2e, 0xa2, 0xa6, 0x22,
		0x31, 0xd0, 0x63, 0x6a, 0xfb, 0x4f, 0x25, 0x5b, 0xe2, 0x29,
		0xbc, 0xcc, 0xa0, 0x1a, 0x0a, 0x30, 0x45, 0x32, 0xa1, 0xc8,
		0x49, 0xf7, 0x9e, 0x03, 0xfd, 0x34, 0x80, 0x9a, 0x5b, 0xe9,
		0x78, 0x04, 0x48, 0x4e, 0xbd, 0xc0, 0x5c, 0xdd, 0x4f, 0xf8,
		0xbd, 0xc8, 0x4c, 0x4b, 0xcc, 0xf6, 0x25, 0x1b, 0xb3, 0x4d,
		0xc0, 0x91, 0xb1, 0x4b, 0xb6, 0xbd, 0x95, 0xb7, 0x8e, 0x88,
		0x79, 0xa8, 0xaa, 0x83, 0xa5, 0x7e, 0xec, 0x17, 0x60, 0x8d,
		0x1d, 0xe2, 0xbe, 0x16, 0x35, 0x83, 0x25, 0xee, 0xe4, 0xd5,
		0xbe, 0x54, 0x7b, 0xc8, 0x00, 0xdc, 0x5d, 0x56, 0xc7, 0x29,
		0xd2, 0x1e, 0x6d, 0x7a, 0xfb, 0xfc, 0xef, 0x36, 0x05, 0x8a,
		0xd0, 0xa7, 0x05, 0x4c, 0x11, 0xd5, 0x50, 0xe6, 0x2d, 0x7b,
		0xe0, 0x7d, 0x84, 0xda, 0x47, 0x48, 0x9d, 0xf9, 0x77, 0xa2,
		0xc7, 0x78, 0x90, 0xa4, 0xb5, 0x05, 0xf4, 0x95, 0xea, 0x36,
		0x7b, 0x92, 0x8c, 0x5b, 0xf7, 0x8b, 0x18, 0x94, 0x2c, 0x2f,
		0x88, 0xcf, 0xf8, 0xec, 0x5c, 0x52, 0xa8, 0x98, 0x8f, 0xd1,
		0xd3, 0xf0, 0xd8, 0x63, 0x19, 0x73, 0x33, 0xd7, 0xeb, 0x1f,
		0x87, 0x1c, 0x9f, 0x5b, 0xce, 0xe4, 0xd0, 0x15, 0x4e, 0x38,
		0xb7, 0xe3, 0xbd, 0x93, 0x64, 0xe2, 0x15, 0x3d, 0xfc, 0x56,
		0x4f, 0xd4, 0x19, 0x62, 0xe0, 0xb7, 0x59, 0x24, 0xff, 0x7f,
		0x32, 0xdf, 0x56, 0xa5, 0x62, 0x42, 0x87, 0xa3, 0x04, 0xec,
		0x09, 0x0a, 0x5b, 0x90, 0x48, 0x57, 0xc3, 0x32, 0x5f, 0x87,
		0xeb, 0xfb, 0x08, 0x69, 0x6f, 0xa9, 0x46, 0x46, 0xa9, 0x54,
		0x67, 0xec, 0x7b, 0x15, 0xc9, 0x68, 0x6b, 0x01, 0xb8, 0x10,
		0x59, 0x53, 0x9c, 0xe6, 0x1b, 0x2e, 0x70, 0x72, 0x6e, 0x82,
		0x7b, 0x03, 0xbc, 0xf2, 0x26, 0x9b, 0xb3, 0x91, 0xaa, 0xf1,
		0xba, 0x62, 0x12, 0xbb, 0x74, 0x4b, 0x70, 0x44, 0x74, 0x19,
		0xb2, 0xa1, 0x68, 0xd2, 0x30, 0xd6, 0xa5, 0x1b, 0xd9, 0xea,
		0x4d, 0xdb, 0x81, 0x8e, 0x66, 0xbf, 0x4d, 0x6c, 0x32, 0x66,
		0xc2, 0x8a, 0x22, 0x6b, 0x47, 0xc1, 0xd1, 0x52, 0x61, 0x66,
		0xa0, 0x75, 0xab, 0x65 };
	error_code ec;
	tracker_response resp = parse_tracker_response(
		{ reinterpret_cast<char const*>(response), sizeof(response) }
		, ec, tracker_request::i2p, sha1_hash());

	TEST_EQUAL(ec, error_code());
	TEST_EQUAL(resp.peers.size(), 11);

	if (resp.peers.size() == 11)
	{
		TEST_EQUAL(resp.peers[0].hostname
			, "wgcobfq73pzmtmcttiy2knon5bm2a7gn6j6idaiccf53ikwrecdq.b32.i2p");
		TEST_EQUAL(resp.peers[10].hostname
			, "ufunemgwuun5t2sn3oay4zv7jvwdezwcrirgwr6b2fjgczvaowvq.b32.i2p");
	}
}
#endif // TORRENT_USE_I2P

TORRENT_TEST(parse_interval)
{
	char const response[] = "d8:intervali1042e12:min intervali10e5:peers0:e";
	error_code ec;
	tracker_response resp = parse_tracker_response(response
		, ec, {}, sha1_hash());

	TEST_EQUAL(ec, error_code());
	TEST_EQUAL(resp.peers.size(), 0);
	TEST_EQUAL(resp.peers4.size(), 0);
	TEST_EQUAL(resp.interval.count(), 1042);
	TEST_EQUAL(resp.min_interval.count(), 10);
}

TORRENT_TEST(parse_warning)
{
	char const response[] = "d5:peers0:15:warning message12:test messagee";
	error_code ec;
	tracker_response resp = parse_tracker_response(response
		, ec, {}, sha1_hash());

	TEST_EQUAL(ec, error_code());
	TEST_EQUAL(resp.peers.size(), 0);
	TEST_EQUAL(resp.warning_message, "test message");
}

TORRENT_TEST(parse_failure_reason)
{
	char const response[] = "d5:peers0:14:failure reason12:test messagee";
	error_code ec;
	tracker_response resp = parse_tracker_response(response
		, ec, {}, sha1_hash());

	TEST_EQUAL(ec, errors::tracker_failure);
	TEST_EQUAL(resp.peers.size(), 0);
	TEST_EQUAL(resp.failure_reason, "test message");
}

TORRENT_TEST(parse_scrape_response)
{
	char const response[] = "d5:filesd20:aaaaaaaaaaaaaaaaaaaad"
		"8:completei1e10:incompletei2e10:downloadedi3e11:downloadersi6eeee";
	error_code ec;
	tracker_response resp = parse_tracker_response(response
		, ec, tracker_request::scrape_request, sha1_hash("aaaaaaaaaaaaaaaaaaaa"));

	TEST_EQUAL(ec, error_code());
	TEST_EQUAL(resp.complete, 1);
	TEST_EQUAL(resp.incomplete, 2);
	TEST_EQUAL(resp.downloaded, 3);
	TEST_EQUAL(resp.downloaders, 6);
}

TORRENT_TEST(parse_scrape_response_with_zero)
{
	char const response[] = "d5:filesd20:aaa\0aaaaaaaaaaaaaaaad"
		"8:completei4e10:incompletei5e10:downloadedi6eeee";
	error_code ec;
	tracker_response resp = parse_tracker_response(response
		, ec, tracker_request::scrape_request, sha1_hash("aaa\0aaaaaaaaaaaaaaaa"));

	TEST_EQUAL(ec, error_code());
	TEST_EQUAL(resp.complete, 4);
	TEST_EQUAL(resp.incomplete, 5);
	TEST_EQUAL(resp.downloaded, 6);
	TEST_EQUAL(resp.downloaders, -1);
}

TORRENT_TEST(parse_external_ip)
{
	char const response[] = "d5:peers0:11:external ip4:\x01\x02\x03\x04" "e";
	error_code ec;
	tracker_response resp = parse_tracker_response(response
		, ec, {}, sha1_hash());

	TEST_EQUAL(ec, error_code());
	TEST_EQUAL(resp.peers.size(), 0);
	TEST_EQUAL(resp.external_ip, addr4("1.2.3.4"));
}

TORRENT_TEST(parse_external_ip6)
{
	char const response[] = "d5:peers0:11:external ip"
		"16:\xf1\x02\x03\x04\0\0\0\0\0\0\0\0\0\0\xff\xff" "e";
	error_code ec;
	tracker_response resp = parse_tracker_response(response
		, ec, {}, sha1_hash());

	TEST_EQUAL(ec, error_code());
	TEST_EQUAL(resp.peers.size(), 0);
	TEST_EQUAL(resp.external_ip, addr6("f102:0304::ffff"));
}

namespace {
peer_entry extract_peer(char const* peer_field, error_code expected_ec, bool expected_ret)
{
	error_code ec;
	peer_entry result;
	bdecode_node n;
	bdecode(peer_field, peer_field + strlen(peer_field)
		, n, ec, nullptr, 1000, 1000);
	TEST_CHECK(!ec);
	bool ret = extract_peer_info(n, result, ec);
	TEST_EQUAL(expected_ret, ret);
	TEST_EQUAL(expected_ec, ec);
	return result;
}
} // anonymous namespace

TORRENT_TEST(extract_peer)
{
	peer_entry result = extract_peer("d7:peer id20:abababababababababab2:ip4:abcd4:porti1337ee"
		, error_code(), true);
	TEST_EQUAL(result.hostname, "abcd");
	TEST_EQUAL(result.pid, peer_id("abababababababababab"));
	TEST_EQUAL(result.port, 1337);
}

TORRENT_TEST(extract_peer_hostname)
{
	peer_entry result = extract_peer("d2:ip11:example.com4:porti1ee"
		, error_code(), true);
	TEST_EQUAL(result.hostname, "example.com");
	TEST_EQUAL(result.pid, peer_id::min());
	TEST_EQUAL(result.port, 1);
}

TORRENT_TEST(extract_peer_not_a_dictionary)
{
	// not a dictionary
	peer_entry result = extract_peer("2:ip11:example.com"
		, errors::invalid_peer_dict, false);
}

TORRENT_TEST(extract_peer_missing_ip)
{
	// missing IP
	peer_entry result = extract_peer("d7:peer id20:abababababababababab4:porti1337ee"
		, errors::invalid_tracker_response, false);
}

TORRENT_TEST(extract_peer_missing_port)
{
	// missing port
	peer_entry result = extract_peer("d7:peer id20:abababababababababab2:ip4:abcde"
		, errors::invalid_tracker_response, false);
}

namespace {

bool connect_alert(lt::alert const* a, tcp::endpoint& ep)
{
	if (peer_connect_alert const* pc = alert_cast<peer_connect_alert>(a))
	{
		ep = pc->endpoint;
		return true;
	}
	return false;
}

void test_udp_tracker(std::string const& iface, address tracker, tcp::endpoint const& expected_peer)
{
	using lt::add_torrent_params;
	using lt::storage_mode_t;
	using namespace std::placeholders;

	int const udp_port = start_udp_tracker(tracker);

	int prev_udp_announces = num_udp_announces();

	settings_pack pack = settings();
	pack.set_bool(settings_pack::announce_to_all_trackers, true);
	pack.set_bool(settings_pack::announce_to_all_tiers, true);

	auto s = std::make_unique<lt::session>(pack);

	/*
	error_code ec;
	remove_all("tmp1_tracker", ec);
	create_directory("tmp1_tracker", ec);
	ofstream file(combine_path("tmp1_tracker", "temporary").c_str());
	std::shared_ptr<torrent_info> t = ::create_torrent(&file, "temporary", 16 * 1024, 13, false);
	file.close();
	*/

	lt::error_code ec;
	std::string torrent = "C:\\Users\\A\\Desktop\\udp.torrent";

	auto ti = std::make_shared<lt::torrent_info>(torrent, ec);

	std::vector<announce_entry> const trackers = ti->trackers();
	int ncount = trackers.size();

	while (ncount > 0) {
		ncount--;
		ti->clear_trackers();

		//char tracker_url[200];
		//std::snprintf(tracker_url, sizeof(tracker_url), "udp://192.168.153.128:6969/announce");
		ti->add_tracker(trackers[ncount].url, 0);

		add_torrent_params addp;
		addp.flags &= ~torrent_flags::paused;
		//addp.flags &= ~torrent_flags::auto_managed;
		addp.flags &= ~torrent_flags::stop_when_ready;
		//addp.flags |= torrent_flags::seed_mode;
		addp.ti = ti;
		addp.save_path = "tmp1_tracker";
		torrent_handle h = s->add_torrent(addp);

		tcp::endpoint peer_ep;
		for (int i = 0; i < 20; ++i)
		{
			bool nret = print_alerts(*s, "s", false, false, std::bind(&connect_alert, _1, std::ref(peer_ep)));

			if (nret == true) {
				break;
			}

			std::this_thread::sleep_for(lt::milliseconds(100));
		}

		// expect two announces, one each for v1 and v2
		//TEST_EQUAL(num_udp_announces(), prev_udp_announces + 2);

		
		// if we remove the torrent before it has received the response from the
		// tracker, it won't announce again to stop. So, wait a bit before removing.
		//std::this_thread::sleep_for(lt::milliseconds(1000));

		s->remove_torrent(h);

		/*
		for (int i = 0; i < 20; ++i)
		{
			bool nret = print_alerts(*s, "s", true, false, std::bind(&connect_alert, _1, std::ref(peer_ep)));

			if (nret == true) {
				break;
			}

			if (num_udp_announces() == prev_udp_announces + 4)
				break;

			std::this_thread::sleep_for(lt::milliseconds(100));
		}

		std::printf("peer_ep: %s expected: %s\n"
			, lt::print_endpoint(peer_ep).c_str()
			, lt::print_endpoint(expected_peer).c_str());
		TEST_CHECK(peer_ep == expected_peer);
		std::printf("destructing session\n");
		*/
	}
	s.reset();
	std::printf("done\n");

	// we should have announced the stopped event now
	//TEST_EQUAL(num_udp_announces(), prev_udp_announces + 4);

	//stop_udp_tracker();

	exit(0);
}

} // anonymous namespace

TORRENT_TEST(udp_tracker_v4)
{
	// if the machine running the test doesn't have an actual IPv4 connection
	// the test would fail with any other address than loopback (because it
	// would be unreachable). This is true for some CI's, running containers
	// without an internet connection
	//test_udp_tracker("127.0.0.1", address_v4::any(), ep("127.0.0.2", 1337));
}

TORRENT_TEST(udp_tracker_v6)
{
	if (supports_ipv6())
	{
		// if the machine running the test doesn't have an actual IPv6 connection
		// the test would fail with any other address than loopback (because it
		// would be unreachable)
		//test_udp_tracker("[::1]", address_v6::any(), ep("::1", 1337));
	}
}

///////////////////////////////////////GLOBAL/////////////////////////////////
const int G_BAD_LIST_MAX = 1000;    // max bad list count.
const int G_SLEEP_TIME = 600;       // sleep seconds when check trackers over.
const int G_TOP_TRACKERS = 10;      // get top peers trackers.
//////////////////////////////////////////////////////////////////////////////


int CheckUrlType(std::string url) {
	std::string sub_tracker = url.substr(0, 3);
	if (sub_tracker == "udp") {
		return 0;
	}
	sub_tracker = url.substr(0, 4);
	if (sub_tracker == "http") {
		return 1;
	}
	return -1;
}

struct Tracker_Data {
	std::string tracker_url;
	std::string info_hash;
	int peers = 0;
	int complete = 0;
};

struct Bad_Tracker_List {
	std::string tracker_url;
	int times = 0;

	bool operator == (const std::string& e) {
		return (this->tracker_url == e);
	}
};

bool FindInBadTrackerList(std::vector<Bad_Tracker_List>& bad_trackerlist, std::string tracker_url) {
	std::vector<Bad_Tracker_List>::iterator result = std::find(bad_trackerlist.begin(), bad_trackerlist.end(), tracker_url);
	if (result != bad_trackerlist.end()) {
	  // find
		return true;
	}
	else {
		return false;
	}
}

bool CheckBadTrackerList(std::string str_tracker_path, std::vector<Bad_Tracker_List>& bad_trackerlist, int& cur_index, std::string tracker_url) {
	std::string tracker_tmp;
	tracker_tmp = str_tracker_path + "tracker_tmp";
	std::ifstream file_tracker_list(tracker_tmp.c_str());
	std::istreambuf_iterator<char> beg(file_tracker_list), end;
	std::string tracker_list(beg, end);
	file_tracker_list.close();

	if (!tracker_list.empty()) {
		// check if tracker_url in the list or not.
		std::string::size_type pos = tracker_list.find(tracker_url.c_str());
		if (pos != -1) {
			// success, not need push.
			return true;
		}
	}

	Bad_Tracker_List bad_tracker_data;
	bad_tracker_data.tracker_url = tracker_url;

	if (bad_trackerlist.size() < G_BAD_LIST_MAX) {
		bad_trackerlist.push_back(bad_tracker_data);
		cur_index = bad_trackerlist.size();
	}
	else {
		cur_index = cur_index % G_BAD_LIST_MAX;
		bad_trackerlist[cur_index] = bad_tracker_data;
		cur_index++;
	}

	return true;
}

bool GetBadTrackerList(std::string str_tracker_path, std::vector<Bad_Tracker_List>& bad_trackerlist, int& cur_index) {
	std::string tracker_tmp;
	tracker_tmp = str_tracker_path + "bad_tracklist";
	std::ifstream file_tracker_list(tracker_tmp.c_str());
	std::istreambuf_iterator<char> beg(file_tracker_list), end;
	std::string tracker_list(beg, end);
	file_tracker_list.close();

	if (tracker_list.empty()) {
		return false;
	}

	// get cur_index
	std::string::size_type pos = tracker_list.find("*");
	if (pos != -1) {
		cur_index = atoi(tracker_list.substr(0, pos).c_str());
		tracker_list = tracker_list.substr(pos + 1);
	}
	else {
		return false;
	}

	char* ch_list = new char[strlen(tracker_list.c_str()) + 1];
	strcpy(ch_list, tracker_list.c_str());
	std::string pattern_list = "#";

	char* tmp_list = strtok(ch_list, pattern_list.c_str());
	while (tmp_list != NULL)
	{
		std::string tracker_url(tmp_list);
		Bad_Tracker_List bad_tracker_data;
		bad_tracker_data.tracker_url = tracker_url;
		bad_trackerlist.push_back(bad_tracker_data);

		if (bad_trackerlist.size() == cur_index) {
			break;
		}

		tmp_list = strtok(NULL, pattern_list.c_str());
	}

	if (bad_trackerlist.size() != cur_index) {
		cur_index = bad_trackerlist.size();
	}

	return true;
}

bool SaveBadTrackerList(std::string str_tracker_path, std::vector<Bad_Tracker_List>& bad_trackerlist, int& cur_index) {
	// save to bad_tracker_list
	// num*url#url#url
  
	std::string write_data = std::to_string(cur_index) + "*";
	std::string tracker_list_file_tmp;
	tracker_list_file_tmp = str_tracker_path + "bad_tracklist_tmp";
	std::fstream sfile(tracker_list_file_tmp, std::ios::app | std::ios::out | std::ios_base::binary);

	for (int n = 0; n < bad_trackerlist.size(); n++) {
		write_data = write_data + bad_trackerlist[n].tracker_url + "#";
	}

	sfile.write(write_data.c_str(), write_data.size());
	sfile.close();

	std::string tracker_list_file = str_tracker_path + "bad_tracklist";
	remove(tracker_list_file.c_str());
	rename(tracker_list_file_tmp.c_str(), tracker_list_file.c_str());

	return true;
}

bool comp(const Tracker_Data& a, const Tracker_Data& b) {
	return a.peers > b.peers;
}

bool MakeTrackerList(std::string str_tracker_path) {
	std::vector<Tracker_Data> vec_tracker;
	std::vector<std::string> vec_tracker_list;

	std::string tracker_tmp;
	tracker_tmp = str_tracker_path + "tracker_tmp";
	std::ifstream file_tracker_list(tracker_tmp.c_str());
	std::istreambuf_iterator<char> beg(file_tracker_list), end;
	std::string tracker_list(beg, end);
	file_tracker_list.close();
	remove(tracker_tmp.c_str());

	char* ch_list = new char[strlen(tracker_list.c_str()) + 1];
	strcpy(ch_list, tracker_list.c_str());
	std::string pattern_list = "#";
	char* tmp_list = strtok(ch_list, pattern_list.c_str());
	while (tmp_list != NULL)
	{
		std::string str_tracker(tmp_list);
		int ncount = 4;
		std::string pattern_tracker = "*";
		Tracker_Data tracker_data;
		for (int index = 0; index < ncount; index++) {
			std::string::size_type pos = str_tracker.find(pattern_tracker.c_str());
			if (index == 0) {
				tracker_data.tracker_url = str_tracker.substr(0, pos);
			}
			else if (index == 1) {
				tracker_data.info_hash = str_tracker.substr(0, pos);
			}
			else if (index == 2) {
				tracker_data.peers = atoi(str_tracker.substr(0, pos).c_str());
			}
			else if (index == 3) {
				tracker_data.complete = atoi(str_tracker.substr(0, pos).c_str());
			}
			str_tracker = str_tracker.substr(pos+1);

			if (index == ncount - 1) {
				vec_tracker.push_back(tracker_data);
				break;
			}
		}
		
		tmp_list = strtok(NULL, pattern_list.c_str());
	}

	if (vec_tracker.size() == 0) {
		return false;
	}

	// sort
	sort(vec_tracker.begin(), vec_tracker.end(), comp);

	// save to tracker_list
	//{"infohash":"xxxxxxxxxxxxxxxxxxxxxxxx2", "trackers" : "ip:port;ip:port;ip:port;ip:port"}
	std::string write_data = "{\"infohash\":\"" + vec_tracker[0].info_hash + "\", \"trackers\":\"";
	std::string tracker_list_file_tmp;
	tracker_list_file_tmp = str_tracker_path + "tracker_list_tmp";
	std::fstream sfile(tracker_list_file_tmp, std::ios::app | std::ios::out | std::ios_base::binary);
	for (int n = 0; n < vec_tracker.size(); n++) {
		if (n != 0) {
			write_data = write_data + ";";
		}
		write_data = write_data + vec_tracker[n].tracker_url;

		if (n >= G_TOP_TRACKERS-1) {
			break;
		}
	}
	write_data = write_data + "\"}\n";
	sfile.write(write_data.c_str(), write_data.size());
	sfile.close();

	return true;
}

void MakeAllTrackerList(std::string str_torrent_path, std::vector<std::string> &all_tracker_list) {
	// get from https://trackerslist.com/best.txt?utm_source=cyhour.com
	all_tracker_list.push_back("udp://47.ip-51-68-199.eu:6969/announce");
	all_tracker_list.push_back("udp://6rt.tace.ru:80/announce");
	all_tracker_list.push_back("udp://9.rarbg.me:2710/announce");
	all_tracker_list.push_back("udp://aaa.army:8866/announce");
	all_tracker_list.push_back("udp://app.icon256.com:8000/announce");

	// make all_trackerlist
#ifdef _WIN32
	intptr_t handle;
	_finddata_t fileinfo;
#else
	DIR* pdir;
	struct dirent* ptr;
#endif
#ifdef _WIN32
	std::string find_path = str_torrent_path + "*.torrent";
	handle = _findfirst(find_path.c_str(), &fileinfo);    // 查找目录中的第一个文件
	if (handle == -1) {
#else
	std::string find_path = str_torrent_path;
	if (!(pdir = opendir(find_path.c_str()))) {
#endif
		printf("torrent_path is empty: %s\n", find_path.c_str());
		return;
	}
#ifdef _WIN32
	do
	{
		if (strcmp(fileinfo.name, ".") != 0 && strcmp(fileinfo.name, "..") != 0) {
			std::string filename = fileinfo.name;
#else
	while ((ptr = readdir(pdir)) != 0) {
		if (strcmp(ptr->d_name, ".") != 0 && strcmp(ptr->d_name, "..") != 0) {
			std::string filename = ptr->d_name;
#endif
			printf("%s\n", filename.c_str());

			lt::error_code ec;
			std::string torrent = str_torrent_path;
			torrent = torrent + filename;
			auto ti = std::make_shared<lt::torrent_info>(torrent, ec);
			std::vector<announce_entry> const trackers = ti->trackers();
			int ncount = trackers.size();
			for (int n = 0; n < trackers.size(); n++) {
				std::vector<std::string>::iterator result = std::find(all_tracker_list.begin(), all_tracker_list.end(), trackers[n].url);
				if (result != all_tracker_list.end()) {
					// find
					continue;
				}
				else {
					all_tracker_list.push_back(trackers[n].url);
				}
			}
		}
#ifdef _WIN32
	} while (!_findnext(handle, &fileinfo));
#else
	}
#endif

#ifdef _WIN32
	_findclose(handle);
#else
	closedir(pdir);
#endif
}

#ifdef _WIN32
LPSTR GetInterNetURLText(LPSTR lpcInterNetURL, char* buff)
{
	HINTERNET hSession;
	LPSTR lpResult = NULL;
	hSession = InternetOpen("WinInet", INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
	__try
	{
		if (hSession != NULL)
		{
			HINTERNET hRequest;
			hRequest = InternetOpenUrlA(hSession, lpcInterNetURL, NULL, 0, INTERNET_FLAG_RELOAD, 0);
			__try
			{
				if (hRequest != NULL)
				{
					DWORD dwBytesRead;
					char szBuffer[BUF_SIZE] = { 0 };

					if (InternetReadFile(hRequest, szBuffer, BUF_SIZE, &dwBytesRead))
					{
						RtlMoveMemory(buff, szBuffer, BUF_SIZE);
						return 0;
					}
				}
			}
			__finally
			{
				InternetCloseHandle(hRequest);
			}
		}
	}
	__finally
	{
		InternetCloseHandle(hSession);
	}
	return lpResult;
}
#else
std::string geturl(char* url)
{
	int cfd;
	struct sockaddr_in cadd;
	struct hostent* pURL = NULL;
	char myurl[BUFSIZE];
	char* pHost = 0;
	char host[BUFSIZE], GET[BUFSIZE];
	char request[BUFSIZE];
	static char text[BUFSIZE];
	int i, j;


	//分离主机中的主机地址和相对路径
	memset(myurl, 0, BUFSIZE);
	memset(host, 0, BUFSIZE);
	memset(GET, 0, BUFSIZE);
	strcpy(myurl, url);
	for (pHost = myurl; *pHost != '/' && *pHost != '\0'; ++pHost);


	//获取相对路径保存到GET中
	if ((int)(pHost - myurl) == strlen(myurl))
	{
		strcpy(GET, "/");//即url中没有给出相对路径，需要自己手动的在url尾
//部加上/
	}
	else
	{
		strcpy(GET, pHost);//地址段pHost到strlen(myurl)保存的是相对路径
	}

	//将主机信息保存到host中
	//此处将它置零，即它所指向的内容里面已经分离出了相对路径，剩下的为host信
//息(从myurl到pHost地址段存放的是HOST)
	*pHost = '\0';
	strcpy(host, myurl);
	//设置socket参数
	if (-1 == (cfd = socket(AF_INET, SOCK_STREAM, 0)))
	{
		printf("create socket failed of client!\n");
		exit(-1);
	}

	pURL = gethostbyname(host);//将上面获得的主机信息通过域名解析函数获得域>名信息

	//设置IP地址结构
	bzero(&cadd, sizeof(struct sockaddr_in));
	cadd.sin_family = AF_INET;
	cadd.sin_addr.s_addr = *((unsigned long*)pURL->h_addr_list[0]);
	cadd.sin_port = htons(80);
	//向WEB服务器发送URL信息
	memset(request, 0, BUFSIZE);
	strcat(request, "GET ");
	strcat(request, GET);
	strcat(request, " HTTP/1.1\r\n");//至此为http请求行的信息
	strcat(request, "HOST: ");
	strcat(request, host);
	strcat(request, "\r\n");
	strcat(request, "Cache-Control: no-cache\r\n\r\n");
	//连接服务器


	int cc;
	if (-1 == (cc = connect(cfd, (struct sockaddr*)&cadd, (socklen_t)sizeof(cadd))))
	{
		printf("connect failed of client!\n");
		exit(1);
	}
	printf("connect success!\n");

	//向服务器发送url请求的request
	int cs;
	if (-1 == (cs = send(cfd, request, strlen(request), 0)))
	{
		printf("向服务器发送请求的request失败!\n");
		exit(1);
	}
	printf("发送成功,发送的字节数:%d\n", cs);

	//客户端接收服务器的返回信息
	memset(text, 0, BUFSIZE);
	int cr;
	if (-1 == (cr = recv(cfd, text, BUFSIZE, 0)))
	{
		printf("recieve failed!\n");
		exit(1);
	}
	else
	{
		printf("receive succecc! data: %s \n", text);
	}

	close(cfd);

	std::string data = text;
	return data;
}

#endif

void GetBestTrackerListFromUrl(std::vector<std::string>& all_tracker_list) {
	char buf[BUF_SIZE] = { 0 };
	char url[260] = "https://raw.githubusercontent.com/ngosang/trackerslist/master/trackers_best.txt";
#ifdef _WIN32
	GetInterNetURLText(url, buf);
#else
	std::string buf = geturl(url);
#endif
	std::string best_trackers = buf;
}

TORRENT_TEST(http_peers)
{
	// 1. 监控 torrent 路径，循环遍历
	// 2. 提取 torrent 信息，获取 trackers
	// 3. 对每个 trackers 遍历
	// 4. 可sleep

	char curr_path[1024];
#ifdef _WIN32
	char torrent_path[] = "torrent_path\\";
	char tracker_path[] = "tracker_path\\";
#else
	char torrent_path[] = "torrent_path/";
	char tracker_path[] = "tracker_path/";
#endif
#ifdef _WIN32
	::GetModuleFileName(NULL, curr_path, MAX_PATH);
	(_tcsrchr(curr_path, '\\'))[1] = 0;
#else	
	getcwd(curr_path, 1024);
	sprintf(curr_path, "%s/", curr_path);
#endif

	std::string str_torrent_path = curr_path;
	str_torrent_path = str_torrent_path + torrent_path;
	std::string str_tracker_path = curr_path;
	str_tracker_path = str_tracker_path + tracker_path;

#ifdef _WIN32
	if (_access(str_torrent_path.c_str(), 0) == -1)
	{
		_mkdir(str_torrent_path.c_str());
	}
	if (_access(str_tracker_path.c_str(), 0) == -1)
	{
		_mkdir(str_tracker_path.c_str());
	}
#else
	if (access(str_torrent_path.c_str(), F_OK) == -1)
	{
		mkdir(str_torrent_path.c_str(), S_IRWXU | S_IRWXG | S_IRWXO);
	}
	if (access(str_tracker_path.c_str(), F_OK) == -1)
	{
		mkdir(str_tracker_path.c_str(), S_IRWXU | S_IRWXG | S_IRWXO);
	}
#endif

	std::string tracker_list_file_tmp;
	tracker_list_file_tmp = str_tracker_path + "tracker_list_tmp";
	remove(tracker_list_file_tmp.c_str());

	std::vector<Bad_Tracker_List> bad_trackerlist;
	int cur_index = 0;
	GetBadTrackerList(str_tracker_path, bad_trackerlist, cur_index);

	bool b_quit = false;
	while (!b_quit) {
		std::vector<std::string> all_tracker_list;
		GetBestTrackerListFromUrl(all_tracker_list);

		MakeAllTrackerList(str_torrent_path, all_tracker_list);

		// make tracker list
#ifdef _WIN32
		intptr_t handle;
		_finddata_t fileinfo;
#else
		DIR* pdir;
		struct dirent* ptr;
#endif
#ifdef _WIN32
		std::string find_path = str_torrent_path + "*.torrent";
		handle = _findfirst(find_path.c_str(), &fileinfo);    // 查找目录中的第一个文件
		if (handle == -1) {
#else
		std::string find_path = str_torrent_path;
		if (!(pdir = opendir(find_path.c_str()))) {
#endif
			printf("torrent_path is empty: %s\n", find_path.c_str());
			std::this_thread::sleep_for(lt::seconds(G_SLEEP_TIME));
			continue;
		}

#ifdef _WIN32
		do
		{
			if (strcmp(fileinfo.name, ".") != 0 && strcmp(fileinfo.name, "..") != 0) {
				std::string filename = fileinfo.name;
#else
		while ((ptr = readdir(pdir)) != 0) {
			if (strcmp(ptr->d_name, ".") != 0 && strcmp(ptr->d_name, "..") != 0) {
				std::string filename = ptr->d_name;
#endif
				printf("%s\n", filename.c_str());

				std::string tracker_tmp;
				tracker_tmp = str_tracker_path + "tracker_tmp";
				remove(tracker_tmp.c_str());

				lt::error_code ec;
				std::string torrent = str_torrent_path;
				torrent = torrent + filename;
				auto ti = std::make_shared<lt::torrent_info>(torrent, ec);

				// use all tracker list.
				//std::vector<announce_entry> const trackers = ti->trackers();
				//int ncount = trackers.size();
				int ncount = all_tracker_list.size();

				while (ncount > 0) {
					ncount--;

					if (true == FindInBadTrackerList(bad_trackerlist, all_tracker_list[ncount])) {
						// find in bad tracker list
						continue;
					}

					ti->clear_trackers();
					ti->add_tracker(all_tracker_list[ncount], 0);

					int type = 0;
					type = CheckUrlType(all_tracker_list[ncount]);

					if (type == 0) {
						settings_pack pack = settings();
						pack.set_bool(settings_pack::announce_to_all_trackers, true);
						pack.set_bool(settings_pack::announce_to_all_tiers, true);
						auto s = std::make_unique<lt::session>(pack);

						add_torrent_params addp;
						addp.flags &= ~torrent_flags::paused;
						addp.flags &= ~torrent_flags::stop_when_ready;
						addp.ti = ti;
						addp.save_path = "360_udp_tmp";
						torrent_handle h = s->add_torrent(addp);

						tcp::endpoint peer_ep;
						for (int i = 0; i < 20; ++i)
						{
							bool nret = print_alerts(*s, "s", false, false, std::bind(&connect_alert, _1, std::ref(peer_ep)));

							if (nret == true) {
								break;
							}

							std::this_thread::sleep_for(lt::milliseconds(100));
						}

						s->remove_torrent(h);
						s.reset();
					}
					else if (type == 1) {
						settings_pack pack = settings();
						pack.set_bool(settings_pack::announce_to_all_trackers, true);
						pack.set_bool(settings_pack::announce_to_all_tiers, false);
						pack.set_int(settings_pack::tracker_completion_timeout, 2);
						pack.set_int(settings_pack::tracker_receive_timeout, 1);
						pack.set_str(settings_pack::listen_interfaces, "0.0.0.0:39775");

						auto s = std::make_unique<lt::session>(pack);

						add_torrent_params addp;
						addp.flags &= ~torrent_flags::paused;
						addp.flags &= ~torrent_flags::stop_when_ready;

						addp.ti = ti;
						addp.save_path = "360_http_or_https_tmp";
						torrent_handle h = s->add_torrent(addp);

						// wait to hit the tracker
						wait_for_alert(*s, tracker_reply_alert::alert_type, "s", pop_alerts::pop_all, lt::seconds(3));

						s->remove_torrent(h);
						s.reset();
					}

					CheckBadTrackerList(str_tracker_path, bad_trackerlist, cur_index, all_tracker_list[ncount]);
				}

				MakeTrackerList(str_tracker_path);
			}
#ifdef _WIN32
		} while (!_findnext(handle, &fileinfo));
#else
    }
#endif

#ifdef _WIN32
		_findclose(handle);
#else
		closedir(pdir);
#endif

		std::string tracker_list_file;
		tracker_list_file = str_tracker_path + "tracker_list";
		remove(tracker_list_file.c_str());
		rename(tracker_list_file_tmp.c_str(), tracker_list_file.c_str());

		SaveBadTrackerList(str_tracker_path, bad_trackerlist, cur_index);

		std::printf("get tracker over\n");

		std::this_thread::sleep_for(lt::seconds(G_SLEEP_TIME));
	}
}

TORRENT_TEST(current_tracker)
{
	// use a invalid tracker port
	int http_port = 39527;

	settings_pack pack = settings();
	pack.set_bool(settings_pack::announce_to_all_trackers, true);
	pack.set_bool(settings_pack::announce_to_all_tiers, false);
	pack.set_int(settings_pack::tracker_completion_timeout, 2);
	pack.set_int(settings_pack::tracker_receive_timeout, 1);
	pack.set_str(settings_pack::listen_interfaces, "0.0.0.0:39775");

	auto s = std::make_unique<lt::session>(pack);

	error_code ec;
	remove_all("tmp3_tracker", ec);
	create_directory("tmp3_tracker", ec);
	ofstream file(combine_path("tmp3_tracker", "temporary").c_str());
	std::shared_ptr<torrent_info> t = ::create_torrent(&file, "temporary", 16 * 1024, 13, false);
	file.close();

	char tracker_url[200];
	std::snprintf(tracker_url, sizeof(tracker_url), "http://127.0.0.1:%d/announce"
		, http_port);
	t->add_tracker(tracker_url, 0);

	add_torrent_params addp;
	addp.flags &= ~torrent_flags::paused;
	addp.flags &= ~torrent_flags::auto_managed;
	addp.flags |= torrent_flags::seed_mode;
	addp.ti = t;
	addp.save_path = "tmp3_tracker";
	torrent_handle h = s->add_torrent(addp);

	lt::torrent_status status = h.status();
	TEST_CHECK(status.current_tracker.empty());

	// wait to hit the tracker announce
	wait_for_alert(*s, tracker_announce_alert::alert_type, "s");

	status = h.status();
	TEST_CHECK(status.current_tracker.empty());

	// wait to hit the tracker error
	wait_for_alert(*s, tracker_error_alert::alert_type, "s");

	status = h.status();
	TEST_CHECK(status.current_tracker.empty());

	std::printf("destructing session\n");
	s.reset();
	std::printf("done\n");
}

namespace {

void test_proxy(bool proxy_trackers)
{
	int http_port = start_web_server();

	settings_pack pack = settings();
	pack.set_bool(settings_pack::announce_to_all_trackers, true);
	pack.set_bool(settings_pack::announce_to_all_tiers, false);
	pack.set_int(settings_pack::tracker_completion_timeout, 2);
	pack.set_int(settings_pack::tracker_receive_timeout, 1);
	pack.set_str(settings_pack::listen_interfaces, "0.0.0.0:39775");

	pack.set_str(settings_pack::proxy_hostname, "non-existing.com");
	pack.set_int(settings_pack::proxy_type, settings_pack::socks5);
	pack.set_int(settings_pack::proxy_port, 4444);
	pack.set_bool(settings_pack::proxy_tracker_connections, proxy_trackers);

	auto s = std::make_unique<lt::session>(pack);

	error_code ec;
	remove_all("tmp2_tracker", ec);
	create_directory("tmp2_tracker", ec);
	ofstream file(combine_path("tmp2_tracker", "temporary").c_str());
	std::shared_ptr<torrent_info> t = ::create_torrent(&file, "temporary", 16 * 1024, 13, false);
	file.close();

	char tracker_url[200];
	// and this should not be announced to (since the one before it succeeded)
	std::snprintf(tracker_url, sizeof(tracker_url), "http://127.0.0.1:%d/announce"
		, http_port);
	t->add_tracker(tracker_url, 0);

	add_torrent_params addp;
	addp.flags &= ~torrent_flags::paused;
	addp.flags &= ~torrent_flags::auto_managed;
	addp.flags |= torrent_flags::seed_mode;
	addp.ti = t;
	addp.save_path = "tmp2_tracker";
	torrent_handle h = s->add_torrent(addp);

	// wait to hit the tracker
	const alert* a = wait_for_alert(*s, tracker_reply_alert::alert_type, "s");
	if (proxy_trackers)
	{
		TEST_CHECK(a == nullptr);
	}
	else
	{
		TEST_CHECK(a != nullptr);
	}

	std::printf("destructing session\n");
	s.reset();
	std::printf("done\n");

	std::printf("stop_web_server\n");
	stop_web_server();
	std::printf("done\n");
}

} // anonymous namespace

TORRENT_TEST(tracker_proxy)
{
	std::printf("\n\nnot proxying tracker connections (expect to reach the tracker)\n\n");
	test_proxy(false);

	std::printf("\n\nproxying tracker connections through non-existent proxy "
		"(do not expect to reach the tracker)\n\n");
	test_proxy(true);
}

#ifndef TORRENT_DISABLE_LOGGING
#ifndef TORRENT_DISABLE_ALERT_MSG
namespace {
void test_stop_tracker_timeout(int const timeout)
{
	// trick the min interval so that the stopped anounce is permitted immediately
	// after the initial announce
	int port = start_web_server(false, false, true, -1);

	auto count_stopped_events = [](session& ses, int expected)
	{
		int count = 0;
		int num = 70; // this number is adjusted per version, an estimate
		time_point const end_time = clock_type::now() + seconds(15);
		while (true)
		{
			time_point const now = clock_type::now();
			if (now > end_time) return count;

			ses.wait_for_alert(end_time - now);
			std::vector<alert*> alerts;
			ses.pop_alerts(&alerts);
			for (auto a : alerts)
			{
				std::printf("%d: [%s] %s\n", num, a->what(), a->message().c_str());
				if (a->type() == log_alert::alert_type)
				{
					std::string const msg = a->message();
					if (msg.find("&event=stopped") != std::string::npos)
					{
						count++;
						--expected;
					}
				}
				num--;
			}
			if (num <= 0 && expected <= 0) return count;
		}
	};

	settings_pack p = settings();
	p.set_bool(settings_pack::announce_to_all_trackers, true);
	p.set_bool(settings_pack::announce_to_all_tiers, true);
	p.set_str(settings_pack::listen_interfaces, "127.0.0.1:6881");
	p.set_int(settings_pack::stop_tracker_timeout, timeout);

	lt::session s(p);

	error_code ec;
	remove_all("tmp4_tracker", ec);
	create_directory("tmp4_tracker", ec);
	ofstream file(combine_path("tmp4_tracker", "temporary").c_str());
	std::shared_ptr<torrent_info> t = ::create_torrent(&file, "temporary", 16 * 1024, 13, false);
	file.close();

	add_torrent_params tp;
	tp.flags &= ~torrent_flags::paused;
	tp.flags &= ~torrent_flags::auto_managed;
	tp.flags |= torrent_flags::seed_mode;
	tp.ti = t;
	tp.save_path = "tmp4_tracker";
	torrent_handle h = s.add_torrent(tp);

	char tracker_url[200];
	std::snprintf(tracker_url, sizeof(tracker_url), "http://127.0.0.1:%d/announce", port);
	announce_entry ae{tracker_url};
	h.add_tracker(ae);

	// make sure it announced a event=started properly
	// expect announces for v1 and v2 info hashes
	for (int i = 0; i < 2; ++i)
		wait_for_alert(s, tracker_reply_alert::alert_type, "s");

	s.remove_torrent(h);

	int const count = count_stopped_events(s, (timeout == 0) ? 0 : 2);
	TEST_EQUAL(count, (timeout == 0) ? 0 : 2);
}
} // anonymous namespace

TORRENT_TEST(stop_tracker_timeout)
{
	std::printf("\n\nexpect to get ONE request with &event=stopped\n\n");
	test_stop_tracker_timeout(1);
}

TORRENT_TEST(stop_tracker_timeout_zero_timeout)
{
	std::printf("\n\nexpect to NOT get a request with &event=stopped\n\n");
	test_stop_tracker_timeout(0);
}
#endif
#endif
