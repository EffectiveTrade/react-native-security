import { NativeModules } from 'react-native';
import { ISecurityV2 } from './SecurityV2.types';

const SecurityV2Module = NativeModules.SecurityV2;

interface INativeError {
  code: number | string;
  message?: string;
  subCode?: number | string;
}

function correctError(error: INativeError | string) {
  if (typeof error === 'string') {
    error = JSON.parse(error) as INativeError;
  }

  if (error.message) {
    error = JSON.parse(error.message) as INativeError;
  }

  error.code = parseInt(`${error.code}`, 10);

  if (error.subCode !== undefined) {
    const maybeNumber = parseInt(`${error.subCode}`, 10);
    error.subCode = !isNaN(maybeNumber) ? maybeNumber : error.subCode;
  }

  return error;
}

function correctErrorCatch(error: INativeError | string) {
  return Promise.reject(correctError(error));
}

export class SecurityV2 implements ISecurityV2 {
  public clean(options?: {}): Promise<void> {
    return SecurityV2Module.clean(options).catch(correctErrorCatch);
  }

  public lock(options?: {}): Promise<void> {
    return SecurityV2Module.lock(options).catch(correctErrorCatch);
  }

  public read(options?: {}): Promise<string | undefined> {
    return SecurityV2Module.read(options).catch(correctErrorCatch);
  }

  public save(creds: string | undefined, options?: {}): Promise<void> {
    return SecurityV2Module.save(creds, options).catch(correctErrorCatch);
  }

  public setUnlockBiometry(options?: {}): Promise<void> {
    const promise = SecurityV2Module.setUnlockBiometry(options).catch(correctErrorCatch);
    (promise as any).cancel = () => {
      return this.cancelBiometry();
    };
    return promise;
  }

  public cancelBiometry(options?: {}): Promise<void> {
    return SecurityV2Module.cancelBiometry(options).catch(correctErrorCatch);
  }

  public async setUnlockCode(code: string, options?: {}): Promise<void> {
    return SecurityV2Module.setUnlockCode(code, options).catch(correctErrorCatch);
  }

  public unlockByBiometry(options?: {}): Promise<void> {
    const promise = SecurityV2Module.unlockByBiometry(options).catch(correctErrorCatch);
    (promise as any).cancel = () => {
      return this.cancelBiometry();
    };

    return promise;
  }

  public unlockByCode(code: string, options?: {}): Promise<void> {
    return SecurityV2Module.unlockByCode(code, options).catch(correctErrorCatch);
  }

  static hasFingerPrintChanged(): Promise<boolean> {
    return new Promise((resolve, reject) => {
      return SecurityV2Module.hasFingerPrintChanged(error => {
        reject(correctError(error));
      }, result => {
        resolve(result);
      })
    });
  };
}
