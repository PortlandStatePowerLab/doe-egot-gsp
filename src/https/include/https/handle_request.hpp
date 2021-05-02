#include "server_certificates.hpp"

#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/beast/version.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl/stream.hpp>
#include <boost/config.hpp>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <string>
#include <thread>

namespace beast = boost::beast;   // from <boost/beast.hpp>
namespace http = beast::http;     // from <boost/beast/http.hpp>
namespace net = boost::asio;      // from <boost/asio.hpp>
namespace ssl = boost::asio::ssl; // from <boost/asio/ssl.hpp>



// This function produces an HTTP response for the given
// request. The type of the response object depends on the
// contents of the request, so the interface requires the
// caller to pass a generic lambda for receiving the response.
template <class Body, class Allocator, class Send>
void HandleRequest(
    std::shared_ptr<std::string> doc_root,
    http::request<Body, http::basic_fields<Allocator>> &&req,
    Send &&send)
{
    // Returns a bad request response
    auto const bad_request =
        [&req](beast::string_view why) {
            http::response<http::string_body> res{http::status::bad_request, req.version()};
            res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
            res.set(http::field::content_type, "text/html");
            res.keep_alive(req.keep_alive());
            res.body() = std::string(why);
            res.prepare_payload();
            return res;
        };

    // Returns a not found response
    auto const not_found =
        [&req](beast::string_view target) {
            http::response<http::string_body> res{http::status::not_found, req.version()};
            res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
            res.set(http::field::content_type, "text/html");
            res.keep_alive(req.keep_alive());
            res.body() = "The resource '" + std::string(target) + "' was not found.";
            res.prepare_payload();
            return res;
        };

    // Returns a server error response
    auto const server_error =
        [&req](beast::string_view what) {
            http::response<http::string_body> res{http::status::internal_server_error, req.version()};
            res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
            res.set(http::field::content_type, "text/html");
            res.keep_alive(req.keep_alive());
            res.body() = "An error occurred: '" + std::string(what) + "'";
            res.prepare_payload();
            return res;
        };

    // Make sure we can handle the method
    if (req.method() != http::verb::get &&
        req.method() != http::verb::post &&
        req.method() != http::verb::put &&
        req.method() != http::verb::delete_ && 
        req.method() != http::verb::head)
        return send(bad_request("Unknown HTTP-method"));

    // Request path must be absolute and not contain "..".
    if( req.target().empty() ||
        req.target()[0] != '/' ||
        req.target().find("..") != beast::string_view::npos)
        return send(bad_request("Illegal request-target"));

    // Build the path to the request
    std::string path = static_cast<std::string>(req.target());
    if(req.target().back() == '/')
    {
        path.append("dcap");
    }

    beast::error_code ec;
    http::file_body::value_type body;
    if (req.method() == http::verb::get)
    {

        std::string res_body = R"(<?xml version="1.0" encoding="utf-8"?>
                <DeviceCapability pollRate="900" href="http://uri1" xmlns="urn:ieee:std:2030.5:ns">
                <CustomerAccountListLink all="0" href="http://uri1" />
                <DemandResponseProgramListLink all="0" href="http://uri1" />
                <DERProgramListLink all="0" href="http://uri1" />
                <FileListLink all="0" href="http://uri1" />
                <MessagingProgramListLink all="0" href="http://uri1" />
                <PrepaymentListLink all="0" href="http://uri1" />
                <ResponseSetListLink all="0" href="http://uri1" />
                <TariffProfileListLink all="0" href="http://uri1" />
                <TimeLink href="http://uri1" />
                <UsagePointListLink all="0" href="http://uri1" />
                <EndDeviceListLink all="0" href="http://uri1" />
                <MirrorUsagePointListLink all="0" href="http://uri1" />
                <SelfDeviceLink href="http://uri1" />
                </DeviceCapability>)";
        
        // Respond to GET request
        http::response<http::string_body> res{
            http::status::ok, req.version()
        };
        res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
        res.set(http::field::content_type, "application/sep+xml");
        res.keep_alive(req.keep_alive());
        res.body() = res_body;
        res.prepare_payload();
        return send(std::move(res));
    }

    if (req.method() == http::verb::post)
    {
        boost::beast::string_view content_type = req[http::field::content_type];
		if (content_type != "application/sep+xml")
		{
			return send(bad_request("Bad request"));
		}

        std::cout << req.body() << std::endl;

        // Respond to POST request
        http::response<http::file_body> res{
            std::piecewise_construct,
            std::make_tuple(std::move(body)),
            std::make_tuple(http::status::created , req.version())};
        res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
        res.set(http::field::location, "/blob");
        res.keep_alive(req.keep_alive());
        return send(std::move(res));
    }

    // Handle an unknown error
    if (ec)
        return send(server_error(ec.message()));

}
