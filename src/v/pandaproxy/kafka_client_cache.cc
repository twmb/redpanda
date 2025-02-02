/*
 * Copyright 2022 Redpanda Data, Inc.
 *
 * Use of this software is governed by the Business Source License
 * included in the file licenses/BSL.md
 *
 * As of the Change Date specified in that file, in accordance with
 * the Business Source License, use of this software will be governed
 * by the Apache License, Version 2.0
 */

#include "pandaproxy/kafka_client_cache.h"

#include "pandaproxy/logger.h"
#include "random/generators.h"
#include "ssx/future-util.h"

#include <seastar/core/loop.hh>

#include <chrono>

namespace pandaproxy {

kafka_client_cache::kafka_client_cache(
  YAML::Node const& cfg,
  size_t max_size,
  std::chrono::milliseconds keep_alive,
  ss::timer<ss::lowres_clock>& clean_and_evict_timer)
  : _config{cfg}
  , _cache_max_size{max_size}
  , _keep_alive{keep_alive}
  , _clean_and_evict_timer{clean_and_evict_timer} {}

client_ptr kafka_client_cache::make_client(
  credential_t user, config::rest_authn_method authn_method) {
    kafka::client::configuration cfg{
      to_yaml(_config, config::redact_secrets::no)};

    // Set the principal when the request is using HTTP Basic AuthN
    if (authn_method == config::rest_authn_method::http_basic) {
        // Need to specify type or else bad any_cast runtime error
        cfg.sasl_mechanism.set_value(ss::sstring{"SCRAM-SHA-256"});
        cfg.scram_username.set_value(std::move(user.name));
        cfg.scram_password.set_value(std::move(user.pass));
    }

    return ss::make_lw_shared<kafka::client::client>(
      to_yaml(cfg, config::redact_secrets::no));
}

client_ptr kafka_client_cache::fetch_or_insert(
  credential_t user, config::rest_authn_method authn_method) {
    auto& inner_list = _cache.get<underlying_list>();
    auto& inner_hash = _cache.get<underlying_hash>();
    ss::sstring k{user.name};
    auto it_hash = inner_hash.find(k);

    client_ptr client;

    // When no client is found ...
    if (it_hash == inner_hash.end()) {
        if (_cache.size() >= _cache_max_size) {
            if (!_cache.empty()) {
                using namespace std::chrono_literals;

                auto item = inner_list.back();
                vlog(plog.debug, "Cache size reached, evicting {}", item.key);
                inner_list.pop_back();
                _evicted_items.push_back(std::move(item));

                // If the timer is not armed, then trigger it for a few seconds
                // from now. If the timer is armed and it won't run until far
                // into the future, then trigger it a few seconds from now. If
                // the timer is armed and it will run soon, then do nothing.
                auto window = ss::lowres_clock::now() + 1s;
                if (
                  !_clean_and_evict_timer.armed()
                  || (_clean_and_evict_timer.armed() && _clean_and_evict_timer.get_timeout() > window)) {
                    _clean_and_evict_timer.rearm(window);
                }
            }
        }

        vlog(plog.debug, "Make client for user {}", k);

        client = make_client(user, authn_method);
        inner_list.emplace_front(k, client);
    } else {
        // If the passwords don't match, update the password on the client, so
        // that it can reconnect.
        if (it_hash->client->config().scram_password.value() != user.pass) {
            vlog(plog.debug, "Updating password for user {}", k);
            it_hash->client->config().scram_password.set_value(user.pass);
        } else {
            vlog(plog.debug, "Reuse client for user {}", k);
        }

        client = it_hash->client;

        // Convert hash iterator to list iterator
        auto it_list = _cache.project<underlying_list>(it_hash);

        // Update the timestamp and relocate the element
        // to the front
        inner_list.modify(it_list, [](timestamped_user& item) {
            item.last_used = timestamped_user::clock::now();
        });
        inner_list.relocate(inner_list.begin(), it_list);
    }

    return client;
}

namespace {
template<typename List, typename Pred>
ss::future<> remove_client_if(List& list, Pred pred) {
    std::list<typename List::value_type> remove;
    auto first = list.begin();
    auto last = list.end();
    while (first != last) {
        if (pred(*first)) {
            remove.push_back(std::move(*first));
            list.erase(first++);
        } else {
            ++first;
        }
    }
    for (auto& item : remove) {
        co_await item.client->stop().handle_exception(
          [&item](std::exception_ptr ex) {
              // The stop failed
              vlog(
                plog.debug,
                "Stale client {} stop already happened {}",
                item.key,
                ex);
          });
    }
}
} // namespace

ss::future<> kafka_client_cache::clean_stale_clients() {
    constexpr auto is_expired = [](std::chrono::milliseconds keep_alive) {
        auto now = timestamped_user::clock::now();
        return [keep_alive, now](const timestamped_user& item) {
            return now >= (item.last_used + keep_alive);
        };
    };
    auto& inner_list = _cache.get<underlying_list>();
    co_await remove_client_if(inner_list, is_expired(_keep_alive));

    constexpr auto always = [](auto&&) { return true; };
    co_await remove_client_if(_evicted_items, always);
}

ss::future<> kafka_client_cache::stop() {
    constexpr auto always = [](auto&&) { return true; };
    auto& inner_list = _cache.get<underlying_list>();
    co_await remove_client_if(inner_list, always);
    co_await remove_client_if(_evicted_items, always);
}

size_t kafka_client_cache::size() const { return _cache.size(); }
size_t kafka_client_cache::max_size() const { return _cache_max_size; }

} // namespace pandaproxy
