/*
 * Copyright (c) 2026 Harmony Contributors.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef VPN_NETWORK_CONFIG_H
#define VPN_NETWORK_CONFIG_H

#include <string>
#include <utility>
#include <vector>
#include "sysvpn_config.h"

namespace OHOS {
namespace NetManagerStandard {
namespace VpnNetworkStorage {
constexpr size_t MAX_BYTES = 1024 * 1024;
constexpr uint32_t MAX_ADDRESSES = 2000;
constexpr uint32_t MAX_ROUTES = 10000;
constexpr uint32_t MAX_REMOTE_ADDRESSES = 2;
constexpr const char *PREFIX = "vpn-network:1:";

// Store only the base network configuration and the two address arrays.
// Credentials/certificates keep the existing separate, HKS-encrypted path.
inline bool Encode(const SysVpnConfig &config, std::string &encoded)
{
    encoded.clear();
    if (config.addresses_.size() > MAX_ADDRESSES || config.localAddresses_.size() > MAX_ADDRESSES ||
        config.routes_.size() > MAX_ROUTES || config.remoteAddresses_.size() > MAX_REMOTE_ADDRESSES) {
        return false;
    }
    Parcel parcel;
    if (!parcel.SetMaxCapacity(MAX_BYTES) || !config.VpnConfig::Marshalling(parcel) ||
        !config.MarshallingVectorString(parcel, config.remoteAddresses_, MAX_REMOTE_ADDRESSES) ||
        !parcel.WriteUint32(static_cast<uint32_t>(config.localAddresses_.size()))) {
        return false;
    }
    for (const auto &address : config.localAddresses_) {
        if (!address.Marshalling(parcel)) {
            return false;
        }
    }
    if (parcel.GetDataSize() == 0 || parcel.GetDataSize() > MAX_BYTES) {
        return false;
    }
    constexpr char HEX[] = "0123456789abcdef";
    encoded = PREFIX;
    encoded.reserve(encoded.size() + parcel.GetDataSize() * 2);
    const auto *data = reinterpret_cast<const uint8_t *>(parcel.GetData());
    for (size_t i = 0; i < parcel.GetDataSize(); ++i) {
        encoded.push_back(HEX[data[i] >> 4]);
        encoded.push_back(HEX[data[i] & 15]);
    }
    return true;
}

inline int HexDigit(char value)
{
    if (value >= '0' && value <= '9') {
        return value - '0';
    }
    if (value >= 'a' && value <= 'f') {
        return value - 'a' + 10;
    }
    return -1;
}

inline bool Restore(const std::string &encoded, SysVpnConfig &config)
{
    // A legacy row never contained a full network snapshot. Retain its old
    // fields; no guessed prefix or synthetic recovery of discarded entries.
    if (encoded.empty()) {
        return true;
    }
    const std::string prefix(PREFIX);
    if (encoded.compare(0, prefix.size(), prefix) != 0 || encoded.size() <= prefix.size()) {
        return false;
    }
    const size_t size = encoded.size() - prefix.size();
    if (size > MAX_BYTES * 2 || size % 2 != 0) {
        return false;
    }
    std::vector<uint8_t> data;
    data.reserve(size / 2);
    for (size_t i = prefix.size(); i < encoded.size(); i += 2) {
        int high = HexDigit(encoded[i]);
        int low = HexDigit(encoded[i + 1]);
        if (high < 0 || low < 0) {
            return false;
        }
        data.push_back(static_cast<uint8_t>((high << 4) | low));
    }
    Parcel parcel;
    if (!parcel.SetMaxCapacity(MAX_BYTES) || !parcel.WriteBuffer(data.data(), data.size())) {
        return false;
    }
    VpnConfig base;
    std::vector<std::string> remote;
    std::vector<INetAddr> local;
    uint32_t count = 0;
    if (!VpnConfig::UnmarshallingVpnConfig(parcel, &base) || base.vpnId_ != config.vpnId_ ||
        !VpnConfig::UnmarshallingVectorString(parcel, remote, MAX_REMOTE_ADDRESSES) ||
        !parcel.ReadUint32(count) || count > MAX_ADDRESSES) {
        return false;
    }
    for (uint32_t i = 0; i < count; ++i) {
        sptr<INetAddr> address = INetAddr::Unmarshalling(parcel);
        if (address == nullptr) {
            return false;
        }
        local.push_back(*address);
    }
    if (parcel.GetReadPosition() != data.size()) {
        return false;
    }
    // Apply only after every field and the end of the snapshot were checked.
    // Never overwrite the separately decrypted login or certificate members.
    config.addresses_ = std::move(base.addresses_);
    config.routes_ = std::move(base.routes_);
    config.mtu_ = base.mtu_;
    config.isAcceptIPv4_ = base.isAcceptIPv4_;
    config.isAcceptIPv6_ = base.isAcceptIPv6_;
    config.isLegacy_ = base.isLegacy_;
    config.isMetered_ = base.isMetered_;
    config.isBlocking_ = base.isBlocking_;
    config.dnsAddresses_ = std::move(base.dnsAddresses_);
    config.searchDomains_ = std::move(base.searchDomains_);
    config.acceptedApplications_ = std::move(base.acceptedApplications_);
    config.refusedApplications_ = std::move(base.refusedApplications_);
    config.remoteAddresses_ = std::move(remote);
    config.localAddresses_ = std::move(local);
    return true;
}
} // namespace VpnNetworkStorage
} // namespace NetManagerStandard
} // namespace OHOS
#endif // VPN_NETWORK_CONFIG_H
