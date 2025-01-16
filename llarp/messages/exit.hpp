#pragma once

#include "common.hpp"

#include <llarp/path/path_types.hpp>
#include <llarp/util/random.hpp>

namespace llarp
{
    /*
        TODO:
          - change these parameters to uspans where needed after bumping oxenc
          - change std::string sig(64, '\0') --> std::array<unsigned char, 64> sig
    */

    namespace ObtainExitMessage
    {
        // flag: 0 = Exit, 1 = Snode
        inline std::string sign_and_serialize(Ed25519SecretKey sk, uint64_t flag, std::string tx_id)
        {
            oxenc::bt_list_producer btlp;
            std::array<unsigned char, 64> sig;

            {
                auto btdp = btlp.append_dict();

                btdp.append("E", flag);
                btdp.append("T", tx_id);

                if (not crypto::sign(reinterpret_cast<uint8_t*>(sig.data()), sk, to_usv(btdp.view())))
                    throw std::runtime_error{"Error: ObtainExitMessage failed to sign and serialize contents!"};
            }

            btlp.append(ustring_view{sig.data(), sig.size()});
            return std::move(btlp).str();
        }

        inline std::string sign_and_serialize_response(Ed25519SecretKey sk, HopID& txid)
        {
            oxenc::bt_list_producer btlp;
            std::array<unsigned char, 64> sig;
            std::array<unsigned char, 16> nonce;
            randombytes(reinterpret_cast<uint8_t*>(nonce.data()), 16);

            {
                oxenc::bt_dict_producer btdp;

                btdp.append("T", txid.to_view());
                btdp.append("Y", ustring_view{nonce.data(), nonce.size()});

                if (crypto::sign(reinterpret_cast<uint8_t*>(sig.data()), sk, to_usv(btdp.view())))
                    throw std::runtime_error{
                        "Error: ObtainExitMessage response failed to sign and serialize contents!"};
            }

            btlp.append(ustring_view{sig.data(), sig.size()});
            return std::move(btlp).str();
        }
    }  // namespace ObtainExitMessage

    namespace UpdateExitMessage
    {
        inline auto UPDATE_FAILED = "EXIT UPDATE FAILED"sv;

        inline std::string sign_and_serialize(Ed25519SecretKey sk, std::string path_id, std::string tx_id)
        {
            oxenc::bt_list_producer btlp;
            std::array<unsigned char, 64> sig;

            {
                auto btdp = btlp.append_dict();

                btdp.append("P", path_id);
                btdp.append("T", tx_id);

                if (not crypto::sign(reinterpret_cast<uint8_t*>(sig.data()), sk, to_usv(btdp.view())))
                    throw std::runtime_error{"Error: UpdateExitMessage failed to sign and serialize contents!"};
            }

            btlp.append(ustring_view{sig.data(), sig.size()});
            return std::move(btlp).str();
        }

        inline std::string sign_and_serialize_response(Ed25519SecretKey sk, std::string_view tx_id)
        {
            oxenc::bt_list_producer btlp;
            std::array<unsigned char, 64> sig;
            std::array<unsigned char, 16> nonce;
            randombytes(reinterpret_cast<uint8_t*>(nonce.data()), 16);

            {
                oxenc::bt_dict_producer btdp;

                btdp.append("T", tx_id);
                btdp.append("Y", ustring_view{nonce.data(), nonce.size()});

                if (crypto::sign(reinterpret_cast<uint8_t*>(sig.data()), sk, to_usv(btdp.view())))
                    throw std::runtime_error{
                        "Error: UpdateExitMessage response failed to sign and serialize contents!"};
            }

            btlp.append(ustring_view{sig.data(), sig.size()});
            return std::move(btlp).str();
        }
    }  // namespace UpdateExitMessage

    namespace CloseExitMessage
    {
        inline auto UPDATE_FAILED = "CLOSE EXIT FAILED"sv;

        inline std::string sign_and_serialize(const Ed25519SecretKey& sk, std::string tx_id)
        {
            oxenc::bt_list_producer btlp;
            std::array<unsigned char, 64> sig;
            std::array<unsigned char, 16> nonce;
            randombytes(reinterpret_cast<uint8_t*>(nonce.data()), 16);

            {
                auto btdp = btlp.append_dict();

                btdp.append("T", tx_id);
                btdp.append("Y", ustring_view{nonce.data(), nonce.size()});

                if (not crypto::sign(reinterpret_cast<uint8_t*>(sig.data()), sk, to_usv(btdp.view())))
                    throw std::runtime_error{"Error: CloseExitMessage failed to sign and serialize contents!"};
            }

            btlp.append(ustring_view{sig.data(), sig.size()});
            return std::move(btlp).str();
        }

        inline std::string sign_and_serialize_response(Ed25519SecretKey sk, std::string_view tx_id)
        {
            oxenc::bt_list_producer btlp;
            std::array<unsigned char, 64> sig;
            std::array<unsigned char, 16> nonce;
            randombytes(reinterpret_cast<uint8_t*>(nonce.data()), 16);

            {
                oxenc::bt_dict_producer btdp;

                btdp.append("T", tx_id);
                btdp.append("Y", ustring_view{nonce.data(), nonce.size()});

                if (crypto::sign(reinterpret_cast<uint8_t*>(sig.data()), sk, to_usv(btdp.view())))
                    throw std::runtime_error{"Error: CloseExitMessage response failed to sign and serialize contents!"};
            }

            btlp.append(ustring_view{sig.data(), sig.size()});
            return std::move(btlp).str();
        }
    }  // namespace CloseExitMessage
}  // namespace llarp
