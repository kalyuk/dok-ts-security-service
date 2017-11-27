import crypto from 'crypto';
import Hashids from 'hashids';
import {BaseService} from 'dok-ts/base/BaseService';

export class SecurityService extends BaseService {
  public static options = {
    algorithm: 'sha512',
    salt: '0dmfuw42w3d' + (new Date()).getTime(),
    hashLength: 12,
    hashAlphabet: 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890'
  };

  private hashids: Hashids;

  public init() {
    super.init();
    this.hashids = new Hashids(this.config.salt, this.config.hashLength, this.config.hashAlphabet);
  }

  public getHash(string, options: any = {}) {
    const algorithm = options.algorithm || this.config.algorithm;
    const salt = options.salt || this.config.salt;
    const hash = crypto.createHmac(algorithm, salt);
    hash.update(string);
    return hash.digest('hex');
  }

  public hashVerify(string, hash, options) {
    return this.getHash(string, options) === hash;
  }

  public id2Hash(id) {
    return this.hashids.encode(id);
  }

  public hash2Id(hash) {
    const tmp = this.hashids.decode(hash);
    if (tmp && tmp.length) {
      return tmp[0];
    }
    return null;
  }
}