using System.Collections.Generic;
using System.Linq;
using System.Text;
using Org.BouncyCastle.Tls;

namespace CoAP.DTLS
{
    public class TlsPskKeySet
    {
        private Dictionary<string, TlsPskIdentity> _keys = new Dictionary<string, TlsPskIdentity>();

        public int Count {
            get => _keys.Count;
        }

        /// <summary>
        /// Return the i-th element in the key set.
        /// </summary>
        /// <param name="i">index of element to return</param>
        /// <returns>TlsPskIdentity</returns>
        public TlsPskIdentity this[int i] {
            get => _keys.ElementAt(i).Value;
        }

        /// <summary>
        /// Add a key to the key set.  The function will do a minimal check for equality to existing keys in the set.
        /// </summary>
        /// <param name="key">key to be added</param>
        public void AddKey(TlsPskIdentity key) {
            _keys.Add(Encoding.UTF8.GetString(key.GetPskIdentity()), key);
        }

        /// <summary>
        /// Add a key to the key set.  The function will do a minimal check for equality to existing keys in the set.
        /// </summary>
        /// <param name="id">id of the key to be added</param>
        /// <param name="psk">pre-shared key to be added</param>
        public void AddKey(byte[] id, byte[] psk) {
            _keys.Add(Encoding.UTF8.GetString(id), new BasicTlsPskIdentity(id, psk));
        }

        /// <summary>
        /// Remove the given key from the list if it is on it.
        /// </summary>
        /// <param name="key">key to be removed</param>
        public void RemoveKey(TlsPskIdentity key) {
            _keys.Remove(Encoding.UTF8.GetString(key.GetPskIdentity()));
        }

        /// <summary>
        /// Remove the given key from the list if it is on it.
        /// </summary>
        /// <param name="id">id of the key to be removed</param>
        public void RemoveKey(byte[] id) {
            _keys.Remove(Encoding.UTF8.GetString(id));
        }

        /// <summary>
        /// All forall to be used to enumerate the keys in a key set.
        /// </summary>
        /// <returns></returns>
        public TlsPskIdentity GetKey(byte[] id) {
            _keys.TryGetValue(Encoding.UTF8.GetString(id), out TlsPskIdentity key);
            
            return key;
        }
    }
}