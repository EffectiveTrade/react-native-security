import { NativeModules } from 'react-native';
import { RNSecurityErrorEnum } from '../types';
import { ISecurityV2, ISecurityV2Error } from './SecurityV2.types';

const SecurityV2Module = NativeModules.SecurityV2;
const EMPTY_OBJ = {};

interface INativeError {
  code: number | string;
  message?: string;
  subCode?: string;
}

function correctError(error: INativeError): ISecurityV2Error {
  error.code = parseInt(`${error.code}`, 10) as RNSecurityErrorEnum;
  // ✅ error.subCode - необходимости заполнять не было
  return error as ISecurityV2Error;
}

export class SecurityV2 implements ISecurityV2 {
  public initialSetup(options?: {}): Promise<void> {
    return new Promise((resolve, reject) => {
      SecurityV2Module.initialSetup(options, (error: INativeError) => {
        if (error) {
          reject(correctError(error));
        } else {
          resolve();
        }
      });
    });
  }

  public clean(options?: {}): Promise<void> {
    return new Promise((resolve, reject) => {
      SecurityV2Module.clean(options || EMPTY_OBJ, (error: INativeError) => {
        if (error) {
          reject(correctError(error));
        } else {
          resolve();
        }
      });
    });
  }

  public lock(options?: {}): Promise<void> {
    return new Promise((resolve, reject) => {
      SecurityV2Module.lock(options || EMPTY_OBJ, (error: INativeError) => {
        if (error) {
          reject(correctError(error));
        } else {
          resolve();
        }
      });
    });
  }

  public read(options?: {}): Promise<string | undefined> {
    return new Promise((resolve, reject) => {
      SecurityV2Module.read(options || EMPTY_OBJ, (error: INativeError, creds: string) => {
        if (error) {
          reject(correctError(error));
        } else {
          resolve(creds);
        }
      });
    });

  }

  public save(creds: string | undefined, options?: {}): Promise<void> {
    return new Promise((resolve, reject) => {
      SecurityV2Module.save(creds, options || EMPTY_OBJ, (error: INativeError) => {
        if (error) {
          reject(correctError(error));
        } else {
          resolve();
        }
      });
    });
  }

  public setUnlockBiometry(options?: {}): Promise<void> {
    return new Promise((resolve, reject) => {
      SecurityV2Module.setUnlockBiometry(options || EMPTY_OBJ, (error: INativeError) => {
        if (error) {
          reject(correctError(error));
        } else {
          resolve();
        }
      });
    });
  }

  public setUnlockCode(code: string, options?: {}): Promise<void> {
    return new Promise((resolve, reject) => {
      SecurityV2Module.setUnlockCode(code, options || EMPTY_OBJ, (error: INativeError) => {
        if (error) {
          reject(correctError(error));
        } else {
          resolve();
        }
      });
    });
  }

  public unlockByBiometry(options?: {}): Promise<void> {
    return new Promise((resolve, reject) => {
      SecurityV2Module.unlockByBiometry(options || EMPTY_OBJ, (error: INativeError) => {
        if (error) {
          reject(correctError(error));
        } else {
          resolve();
        }
      });
    });
  }

  public unlockByCode(code: string, options?: {}): Promise<void> {
    return new Promise((resolve, reject) => {
      SecurityV2Module.unlockByCode(code, options || EMPTY_OBJ, (error: INativeError) => {
        if (error) {
          reject(correctError(error));
        } else {
          resolve();
        }
      });
    });
  }

  public cancelBiometry(options?: {}): Promise<void> {
    return Promise.resolve();
  }

  public hasFingerPrintChanged(): Promise<boolean> {
    return new Promise((resolve, reject) => {
      return SecurityV2Module.hasFingerPrintChanged((error: INativeError) => {
        reject(error);
      }, (result: boolean) => {
        resolve(result);
      })
    });
  };
}
