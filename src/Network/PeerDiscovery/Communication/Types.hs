module Network.PeerDiscovery.Communication.Types
  ( Signal(..)
  , sendSignal
  , Request(..)
  , FindPeer(..)
  , Ping(..)
  , RequestAddress(..)
  , Response(..)
  , ReturnPeers(..)
  , Pong(..)
  , AddressableAs(..)
  ) where

import Codec.CBOR.Decoding
import Codec.CBOR.Encoding
import Codec.Serialise
import Control.Monad
import Data.Functor.Identity
import Data.Monoid
import Network.Socket hiding (recvFrom, sendTo)
import Network.Socket.ByteString

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
sendSignal sock signal Peer{..} =
  void $ sendTo sock (serialise' signal) (SockAddrInet peerPort peerAddress)

----------------------------------------

data Request = FindPeerR !FindPeer
             | PingR !Ping
             | RequestAddressR !RequestAddress
  deriving (Eq, Show)

data FindPeer = FindPeer !(Maybe PortNumber) !PeerId
  deriving (Eq, Show)

data Ping = Ping
  deriving (Eq, Show)

data RequestAddress = RequestAddress !PortNumber
  deriving (Eq, Show)

instance Serialise Request where
  encode = \case
    FindPeerR (FindPeer mport nid) ->
      encodeListLen 3 <> encodeWord 0 <> encodePortNumber mport <> encode nid
    PingR Ping ->
      encodeListLen 1 <> encodeWord 1
    RequestAddressR (RequestAddress port) ->
      encodeListLen 2 <> encodeWord 2 <> encodePortNumber (Identity port)
  decode = do
    len <- decodeListLen
    decodeWord >>= \case
      0 -> FindPeerR <$> do
        matchSize 3 "decode(Request).FindPeerR" len
        FindPeer <$> decodePortNumber <*> decode
      1 -> PingR <$> do
        matchSize 1 "decode(Request).PingR" len
        pure Ping
      2 -> RequestAddressR <$> do
        matchSize 2 "decode(Request).RequestAddressR" len
        RequestAddress . runIdentity <$> decodePortNumber
      n -> fail $ "decode(Request): invalid tag: " ++ show n

----------------------------------------

data Response = ReturnPeersR !ReturnPeers
              | PongR !Pong
              | AddressableAsR !AddressableAs
  deriving (Eq, Show)

data ReturnPeers = ReturnPeers ![Peer]
  deriving (Eq, Show)

data Pong = Pong
  deriving (Eq, Show)

data AddressableAs = AddressableAs !Peer
  deriving (Eq, Show)

instance Serialise Response where
  encode = \case
    ReturnPeersR (ReturnPeers peers)    -> encodeListLen 2 <> encodeWord 0 <> encode peers
    PongR Pong                          -> encodeListLen 1 <> encodeWord 1
    AddressableAsR (AddressableAs peer) -> encodeListLen 2 <> encodeWord 2 <> encode peer
  decode = do
    len <- decodeListLen
    decodeWord >>= \case
      0 -> ReturnPeersR <$> do
        matchSize 2 "decode(Response).ReturnPeersR" len
        ReturnPeers <$> decode
      1 -> PongR <$> do
        matchSize 1 "decode(Response).PongR" len
        pure Pong
      2 -> AddressableAsR <$> do
        matchSize 2 "decode(Response).AddressableAsR" len
        AddressableAs <$> decode
      n -> fail $ "decode(Response): invalid tag: " ++ show n
