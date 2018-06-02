{-# LANGUAGE EmptyDataDecls #-}
{-# LANGUAGE RankNTypes #-}
module Network.PeerDiscovery.Communication.Method
  ( CommunicationMethod
  , UdpSocket
  , udpSocket
  , StmRouter
  , stmRouter
  , withStmRouter
  ) where

import Control.Concurrent.MVar
import Control.Concurrent.STM
import Control.Exception
import Control.Monad
import Data.Function
import Network.Socket hiding (recvFrom, sendTo)
import Prelude
import qualified Data.Map.Strict as M
import qualified Network.Socket.ByteString as S

import Network.PeerDiscovery.Types
import Network.PeerDiscovery.Util

type CommunicationMethod cm
   = forall r. PortNumber
  -> (Peer -> CommInterface -> IO r)
  -> IO r

data UdpSocket

-- | Construct communication method based on UDP sockets.
udpSocket
  :: Maybe HostName -- ^ Host name to bind to, if applicable.
  -> CommunicationMethod UdpSocket
udpSocket mhost port k = do
  getAddrInfo (Just hints) mhost (Just $ show port) >>= \case
    []   -> error $ "udpSocket: couldn't create IPv4 UDP socket on port "
                 ++ show port
    (ai:_) -> case mkPeer (addrAddress ai) of
      Nothing -> error $ "udpSocket: couldn't create Peer from "
                      ++ show (addrAddress ai)
      Just peer -> do
        sock <- socket (addrFamily ai) (addrSocketType ai) (addrProtocol ai)
        bracket_ (bind sock (addrAddress ai)) (close sock) $
          k peer $ CommInterface { recvFrom = recvFromImpl sock
                                 , sendTo   = sendToImpl sock
                                 }
  where
    hints = defaultHints { addrFamily = AF_INET
                         , addrFlags = [AI_PASSIVE]
                         , addrSocketType = Datagram
                         }

    recvFromImpl sock = fix $ \loop -> do
      (bytes, source) <- S.recvFrom sock 4096
      case mkPeer source of
        Nothing -> do
          putStrLn $ "recvFrom: couldn't construct Peer from " ++ show source
          loop
        Just peer -> case deserialiseOrFail' bytes of
          Right signal -> return (peer, signal)
          Left err -> do
            putStrLn $ "recvFrom: error while parsing signal: " ++ show err
            loop

    sendToImpl sock = \Peer{..} signal -> void $
      S.sendTo sock (serialise' signal) (SockAddrInet peerPort peerAddress)

----------------------------------------

-- | STM-based router for testing purposes.
newtype StmRouter = StmRouter
  { routerRoutes :: MVar (M.Map Peer (TQueue (Peer, Signal)))
  }

-- | Construct new 'StmRouter' for use in the continuation.
withStmRouter :: (StmRouter -> IO r) -> IO r
withStmRouter k = k . StmRouter =<< newMVar M.empty

-- | Construct communication method based on 'StmRouter'.
stmRouter :: StmRouter -> CommunicationMethod StmRouter
stmRouter StmRouter{..} port k = bracket register unregister $ \route ->
  k peer $ CommInterface
     { recvFrom = atomically $ readTQueue route
     , sendTo   = \dest signal -> readMVar routerRoutes >>= \routes -> do
         case dest `M.lookup` routes of
           Just destRoute -> atomically $ writeTQueue destRoute (peer, signal)
           Nothing        -> putStrLn $ "sendTo (" ++ show peer
                                     ++ "): no route to " ++ show dest
                                     ++ ", discarding message"
     }
  where
    peer = Peer 0 port

    register = modifyMVar routerRoutes $ \routes -> do
      if peer `M.member` routes
        then error $ "register: route to " ++ show peer ++ " already exists"
        else do
          route <- newTQueueIO
          return . (, route) $! M.insert peer route routes

    unregister route = modifyMVar_ routerRoutes $ \routes -> do
      case peer `M.lookup` routes of
        Nothing -> do
          putStrLn $ "unregister: no route to " ++ show peer
          return routes
        Just route'
          | route == route' -> return $! M.delete peer routes
          | otherwise -> do
              putStrLn $ "unregister: route to " ++ show peer
                      ++ " is different than expected"
              return routes
