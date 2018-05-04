module Network.PeerDiscovery.Types
  ( -- * Config
    Config(..)
  , defaultConfig
    -- * Peer
  , Peer(..)
  , mkPeer
    -- * PeerId
  , PeerId
  , mkPeerId
  , peerIdBitSize
  , randomPeerId
  , testPeerIdBit
  , distance
    -- * RpcId
  , RpcId
  , rpcIdBitSize
  , fromRpcId
  , randomRpcId
    -- * Node
  , Node(..)
    -- * RoutingTable
  , NodeInfo(..)
  , RoutingTable(..)
  , RoutingTree(..)
    -- * Request
  , Request(..)
  , FindNode(..)
  , Ping(..)
    -- * Response
  , Response(..)
  , ReturnNodes(..)
  , Pong(..)
    -- * Signal
  , Signal(..)
    -- * ResponseHandler
  , ResponseHandler(..)
  , ResponseHandlers
    -- * Communication abstractions
  , CommInterface(..)
    -- * PeerDiscovery
  , PeerDiscovery(..)
  ) where

import Codec.CBOR.Decoding
import Codec.CBOR.Encoding
import Codec.Serialise
import Control.Concurrent
import Data.Bits
import Data.Functor.Identity
import Data.Monoid
import Data.Typeable
import Network.Socket
import qualified Crypto.Hash as H
import qualified Crypto.PubKey.Ed25519 as C
import qualified Crypto.Random as C
import qualified Data.ByteArray as BA
import qualified Data.ByteString as BS
import qualified Data.Map.Strict as M
import qualified Data.Sequence as S

import Network.PeerDiscovery.Util

data Config = Config
  { configAlpha             :: !Int -- ^ Concurrency parameter.
  , configK                 :: !Int -- ^ Bucket size.
  , configD                 :: !Int -- ^ Number of distinct lookup paths.
  , configB                 :: !Int -- ^ Maximum depth of the routing tree.
  , configMaxTimeouts       :: !Int -- ^ Number of acceptable timeouts before
                                    --   eviction from the routing tree.
  , configResponseTimeout   :: !Int -- ^ Response timeout in microseconds.
  , configSpeedupFactor     :: !Int -- ^ Speedup factor for workers responsible
                                    -- for network maintenance.
  , configLookupTries       :: !Int -- ^ The amount of times we try to lookup
                                    -- peers before concluding that the routing
                                    -- table is corrupt and resetting its state.
  }

defaultConfig :: Config
defaultConfig = Config
  { configAlpha             = 3
  , configK                 = 16
  , configD                 = 8
  , configB                 = 5
  , configMaxTimeouts       = 3
  , configResponseTimeout   = 500000
  , configSpeedupFactor     = 1
  , configLookupTries       = 5
  }

----------------------------------------

-- | IPv4 Peer.
data Peer = Peer
  { peerAddress :: !HostAddress
  , peerPort    :: !PortNumber
  } deriving (Eq, Ord)

instance Show Peer where
  showsPrec p Peer{..} = showsPrec p b1 . ("." ++)
                       . showsPrec p b2 . ("." ++)
                       . showsPrec p b3 . ("." ++)
                       . showsPrec p b4 . (":" ++)
                       . showsPrec p peerPort
    where
      (b1, b2, b3, b4) = hostAddressToTuple peerAddress

mkPeer :: SockAddr -> Maybe Peer
mkPeer (SockAddrInet port host) = Just (Peer host port)
mkPeer _                        = Nothing

----------------------------------------

-- Size of PeerId in bits (256).
peerIdBitSize :: Int
peerIdBitSize = 256

-- | PeerId is the peer identifier derivable from its public key.
newtype PeerId = PeerId Integer
  deriving (Eq, Ord, Serialise)

instance Show PeerId where
  show = (++ "...") . toBinary
    where
      -- Show 16 most significant bits of an identifier.
      toBinary :: PeerId -> String
      toBinary (PeerId x) =
        foldr (\i acc -> (if testBit x i then "1" else "0") ++ acc) ""
          $ enumFromThenTo (peerIdBitSize - 1) (peerIdBitSize - 2) (peerIdBitSize - 16)

-- | Construct 'PeerId' from peer's public key.
mkPeerId :: C.PublicKey -> PeerId
mkPeerId = PeerId . mkInteger . BA.convert . H.hashWith H.Blake2b_256

-- | Generate random 'PeerId' using cryptographically secure RNG.
randomPeerId :: IO PeerId
randomPeerId = PeerId . mkInteger <$> C.getRandomBytes (peerIdBitSize `quot` 8)

-- | Test whether a specific bit of 'PeerId' is set.
testPeerIdBit :: PeerId -> Int -> Bool
testPeerIdBit (PeerId n) k = testBit n (peerIdBitSize - k - 1)

-- | Calculate distance between two peers using xor metric.
distance :: PeerId -> PeerId -> Integer
distance (PeerId a) (PeerId b) = a `xor` b

----------------------------------------

-- | Size of RpcId in bits (160).
rpcIdBitSize :: Int
rpcIdBitSize = 160

-- | Identifier of any RPC call for prevention of address forgery attacks and
-- linking requests with appropriate response handlers.
newtype RpcId = RpcId BS.ByteString
  deriving (Eq, Ord, Show, Serialise)

-- | Extract underlyging ByteString from RpcId.
fromRpcId :: RpcId -> BS.ByteString
fromRpcId (RpcId bs) = bs

-- | Generate random 'RpcId' using cryptographically secure RNG.
randomRpcId :: IO RpcId
randomRpcId = RpcId <$> C.getRandomBytes (rpcIdBitSize `quot` 8)

----------------------------------------

-- | 'Peer' along with its id.
data Node = Node
  { nodeId           :: !PeerId
  , nodePeer         :: !Peer
  } deriving (Eq, Ord, Show)

instance Serialise Node where
  encode Node{..} = encodeListLen 3
                 <> encode nodeId
                 <> encode (htonl peerAddress)
                 <> encodePortNumber (Identity peerPort)
    where
      Peer{..} = nodePeer

  decode = do
    matchSize 3 "decode(Node)" =<< decodeListLen
    nodeId   <- decode
    nodePeer <- Peer <$> (ntohl <$> decode)
                     <*> (runIdentity <$> decodePortNumber)
    pure Node{..}

----------------------------------------

-- | 'Node' along with additional info for 'RoutingTable'.
data NodeInfo = NodeInfo
  { niNode         :: !Node
  , niTimeoutCount :: !Int
  } deriving (Eq, Show)

-- | Routing table.
data RoutingTable = RoutingTable
  { rtId     :: !PeerId
  , rtTree   :: !RoutingTree
  } deriving (Eq, Show)

data RoutingTree = Bucket !(S.Seq NodeInfo)
                 | Split {- 1 -} !RoutingTree {- 0 -} !RoutingTree
  deriving (Eq, Show)

----------------------------------------

data Request = FindNodeR !FindNode
             | PingR !Ping
  deriving (Eq, Show)

data FindNode = FindNode
  { fnPeerId     :: !PeerId
  , fnPublicPort :: !(Maybe PortNumber)
  , fnTargetId   :: !PeerId
  } deriving (Eq, Show)

data Ping = Ping
  { pingReturnPort :: !(Maybe PortNumber)
  } deriving (Eq, Show)

instance Serialise Request where
  encode = \case
    FindNodeR (FindNode peerId mport targetId) ->
         encodeListLen 4 <> encodeWord 0
      <> encode peerId <> encodePortNumber mport <> encode targetId
    PingR (Ping mport) ->
      encodeListLen 2 <> encodeWord 1 <> encodePortNumber mport
  decode = do
    len <- decodeListLen
    decodeWord >>= \case
      0 -> FindNodeR <$> do
        matchSize 4 "decode(Request).FindNodeR" len
        FindNode <$> decode <*> decodePortNumber <*> decode
      1 -> PingR <$> do
        matchSize 2 "decode(Request).PingR" len
        Ping <$> decodePortNumber
      n -> fail $ "decode(Request): invalid tag: " ++ show n

----------------------------------------

data Response = ReturnNodesR !ReturnNodes
              | PongR !Pong
  deriving (Eq, Show)

data ReturnNodes = ReturnNodes ![Node]
  deriving (Eq, Show)

data Pong = Pong
  deriving (Eq, Show)

instance Serialise Response where
  encode = \case
    ReturnNodesR (ReturnNodes peers) ->
      encodeListLen 2 <> encodeWord 0 <> encode peers
    PongR Pong ->
      encodeListLen 1 <> encodeWord 1
  decode = do
    len <- decodeListLen
    decodeWord >>= \case
      0 -> ReturnNodesR <$> do
        matchSize 2 "decode(Response).ReturnNodesR" len
        ReturnNodes <$> decode
      1 -> PongR <$> do
        matchSize 1 "decode(Response).PongR" len
        pure Pong
      n -> fail $ "decode(Response): invalid tag: " ++ show n

----------------------------------------

-- | Represents all incoming and outgoing communication. Each response is signed
-- to ensure the integrity of data and legitimacy of the responder.
data Signal = Request  !RpcId                           !Request
            | Response !RpcId !C.PublicKey !C.Signature !Response
  deriving (Eq, Show)

instance Serialise Signal where
  encode = \case
    Request  rpcId rq  -> encodeListLen 3
                       <> encodeWord 0
                       <> encode rpcId
                       <> encode rq
    Response rpcId pkey signature rsp -> encodeListLen 5
                                      <> encodeWord 1
                                      <> encode rpcId
                                      <> encodePublicKey pkey
                                      <> encodeSignature signature
                                      <> encode rsp
  decode = do
    len <- decodeListLen
    decodeWord >>= \case
      0 -> do
        matchSize 3 "decode(Signal).Request" len
        Request <$> decode <*> decode
      1 -> do
        let label = "decode(Signal).Response"
        matchSize 5 label len
        Response <$> decode
                 <*> decodePublicKey label
                 <*> decodeSignature label
                 <*> decode
      n -> fail $ "decode(Signal): invalid tag: " ++ show n

----------------------------------------

-- | Handler of a specific Request.
data ResponseHandler = forall r. Typeable r => ResponseHandler
  { rhRequest          :: !Request
  , rhRecipient        :: !Node
  , rhTimeoutHandlerId :: !ThreadId
  , rhOnFailure        :: !(IO ())
  , rhHandler          :: !(r -> IO ())
  }

-- | Map of response handlers.
type ResponseHandlers = MVar (M.Map RpcId ResponseHandler)

-- | Abstract interface for communication between peer discovery instances.
data CommInterface = CommInterface
  { recvFrom :: !(IO (Peer, Signal))
  , sendTo   :: !(Peer -> Signal -> IO ())
  }

-- | Primary object of interest.
data PeerDiscovery cm = PeerDiscovery
  { pdBindAddr         :: !Peer
  , pdBootstrapped     :: !(MVar Bool)
  , pdPublicPort       :: !(MVar (Maybe PortNumber))
  , pdPublicKey        :: !C.PublicKey
  , pdSecretKey        :: !C.SecretKey
  , pdCommInterface    :: !CommInterface
  , pdRoutingTable     :: !(MVar RoutingTable)
  , pdResponseHandlers :: !ResponseHandlers
  , pdConfig           :: !Config
  }
