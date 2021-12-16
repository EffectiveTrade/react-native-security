import { NativeModules } from 'react-native';

const NativeAuth = NativeModules.VBNativeAuth;

interface INativeError {
  code: number | string;
  message?: string;
  subCode?: number | string;
}

function correctError(error: INativeError | string) {
  if (typeof error === 'string') {
    error = JSON.parse(error) as INativeError;
  }
  error.code = parseInt(`${error.code}`, 10);

  if (error.subCode !== undefined) {
    const maybeNumber = parseInt(`${error.subCode}`, 10);
    error.subCode = !isNaN(maybeNumber) ? maybeNumber : error.subCode;
  }

  return error;
}

function correctSuccess(r: any) {
  r = JSON.parse(r);
  r.code = parseInt(r.code, 10);
  return r;
}

export default {
  saveCred(login: string, password: string, code: string) {
    return new Promise((resolve, reject) => {
      NativeAuth.SaveCred(
        login,
        password,
        code,
        (error: INativeError) => {
          return reject(correctError(error));
        },
        (success: any) => {
          return resolve(correctSuccess(success));
        }
      );
    });
  },

  unlockByCode(code: string) {
    return new Promise((resolve, reject) => {
      NativeAuth.UnlockByCode(
        code,
        (error: INativeError) => {
          return reject(correctError(error));
        },
        (success: any) => {
          return resolve(correctSuccess(success));
        }
      );
    });
  },

  unlockByBiometry() {
    var rv = new Promise((resolve, reject) => {
      NativeAuth.UnlockByBiometry(
        (error: INativeError) => {
          return reject(correctError(error));
        },
        (success: any) => {
          return resolve(correctSuccess(success));
        }
      );
    });

    (rv as any).cancel = () => {
      NativeAuth.CancelUnlockByBiometry();
    };

    return rv;
  },

  clean() {
    return new Promise((resolve, reject) => {
      NativeAuth.Clean(
        (error: INativeError) => {
          return reject(correctError(error));
        },
        (success: any) => {
          return resolve(correctSuccess(success));
        }
      );
    });
  },

  isSupported() {
    return new Promise((resolve, reject) => {
      NativeAuth.IsSupported(
        (error: INativeError) => {
          return reject(correctError(error));
        },
        (success: any) => {
          return resolve(correctSuccess(success));
        }
      );
    });
  },

  saveCredByBiometry(login: string, password: string) {
    var rv = new Promise((resolve, reject) => {
      NativeAuth.SaveCredByBiometry(
        login,
        password,
        (error: INativeError) => {
          return reject(correctError(error));
        },
        (success: any) => {
          return resolve(correctSuccess(success));
        }
      );
    });

    (rv as any).cancel = () => {
      NativeAuth.CancelSaveCredByBiometry();
    };

    return rv;
  }
};
