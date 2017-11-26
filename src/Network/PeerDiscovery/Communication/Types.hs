module Network.PeerDiscovery.Communication.Types
  ( Signal(..)
  , sendSignal
  , Request(..)
  , FindNode(..)
  , Ping(..)
  , RequestAuth(..)
  , Response(..)
  , ReturnNodes(..)
  , Pong(..)
  , AuthProof(..)
  ) where

import Codec.CBOR.Decoding
import Codec.CBOR.Encoding
import Codec.Serialise
import Control.Monad
import Data.Monoid
import Network.Socket hiding (recvFrom, sendTo)
import Network.Socket.ByteString
import qualified Crypto.Error as C
import qualified Crypto.PubKey.Ed25519 as C
import qualified Data.ByteArray as BA
import qualified Data.ByteString as BS

import Network.PeerDiscovery.Types
import Network.PeerDiscovery.Util

data Signal = Request !RpcId !Request
            | Response !RpcId !Response
  deriving (Eq, Show)

instance Serialise Signal where
  encode = \case
    Request  rpcId rq  -> encodeListLen 3 <> encodeWord 0 <> encode rpcId <> encode rq
    Response rpcId rsp -> encodeListLen 3 <> encodeWord 1 <> encode rpcId <> encode rsp
  decode = do
    matchSize 3 "decode(Signal)" =<< decodeListLen
    decodeWord >>= \case
      0 -> Request  <$> decode <*> decode
      1 -> Response <$> decode <*> decode
      n -> fail $ "decode(Signal): invalid tag: " ++ show n

sendSignal :: Socket -> Signal -> Peer -> IO ()
sendSignal sock signal Peer{..} = do
  let sig = serialise' signal
  putStrLn $ "Sending " ++ show (BS.length sig) ++ " bytes"
  void $ sendTo sock (serialise' signal) (SockAddrInet peerPort peerAddress)

----------------------------------------

data Request = FindNodeR !FindNode
             | PingR !Ping
             | RequestAuthR !RequestAuth
  deriving (Eq, Show)

data FindNode = FindNode !PeerId !(Maybe PortNumber) !PeerId
  deriving (Eq, Show)

data Ping = Ping
  deriving (Eq, Show)

data RequestAuth = RequestAuth !Nonce
  deriving (Eq, Show)

instance Serialise Request where
  encode = \case
    FindNodeR (FindNode peerId mport targetId) ->
         encodeListLen 4 <> encodeWord 0
      <> encode peerId <> encodePortNumber mport <> encode targetId
    PingR Ping ->
      encodeListLen 1 <> encodeWord 1
    RequestAuthR (RequestAuth nonce) ->
      encodeListLen 2 <> encodeWord 2 <> encode nonce
  decode = do
    len <- decodeListLen
    decodeWord >>= \case
      0 -> FindNodeR <$> do
        matchSize 4 "decode(Request).FindNodeR" len
        FindNode <$> decode <*> decodePortNumber <*> decode
      1 -> PingR <$> do
        matchSize 1 "decode(Request).PingR" len
        pure Ping
      2 -> RequestAuthR <$> do
        matchSize 2 "decode(Request).RequestAuthR" len
        RequestAuth <$> decode
      n -> fail $ "decode(Request): invalid tag: " ++ show n

----------------------------------------

data Response = ReturnNodesR !ReturnNodes
              | PongR !Pong
              | AuthProofR !AuthProof
  deriving (Eq, Show)

data ReturnNodes = ReturnNodes ![Node]
  deriving (Eq, Show)

data Pong = Pong
  deriving (Eq, Show)

data AuthProof = AuthProof !C.PublicKey !C.Signature
  deriving (Eq, Show)

instance Serialise Response where
  encode = \case
    ReturnNodesR (ReturnNodes peers) ->
      encodeListLen 2 <> encodeWord 0 <> encode peers
    PongR Pong ->
      encodeListLen 1 <> encodeWord 1
    AuthProofR (AuthProof pkey sig) ->
         encodeListLen 3 <> encodeWord 2
      <> encode (BA.convert pkey :: BS.ByteString)
      <> encode (BA.convert sig  :: BS.ByteString)
  decode = do
    len <- decodeListLen
    decodeWord >>= \case
      0 -> ReturnNodesR <$> do
        matchSize 2 "decode(Response).ReturnNodesR" len
        ReturnNodes <$> decode
      1 -> PongR <$> do
        matchSize 1 "decode(Response).PongR" len
        pure Pong
      2 -> AuthProofR <$> do
        let label = "decode(Response).AuthProofR"
        matchSize 3 label len
        decodeBytes <&> C.publicKey >>= \case
          C.CryptoFailed err  -> fail $ label ++ ": " ++ show err
          C.CryptoPassed pkey -> decodeBytes <&> C.signature >>= \case
            C.CryptoFailed err -> fail $ label ++ ": " ++ show err
            C.CryptoPassed sig -> pure $ AuthProof pkey sig
      n -> fail $ "decode(Response): invalid tag: " ++ show n
