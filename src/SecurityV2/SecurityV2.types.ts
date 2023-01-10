import { RNSecurityErrorEnum } from '../types';

export interface ISecurityV2Error {
  readonly code: RNSecurityErrorEnum;
  readonly message?: string;
  readonly subCode?: string;
}

/**
 * Защищённое хранилище.
 */
export interface ISecurityV2 {
  /**
   * Открыть хранилище при помощи кода. Количество попыток ограничено.
   * @param code
   * @param options
   * @exception RNSecurityError
   */
  unlockByCode(code: string, options?: {}): Promise<void>;
  /**
   * Открыть хранилище при помощи биометрии. Количество попыток ограничено.
   * @param options
   * @exception RNSecurityError
   */
  unlockByBiometry(options?: {}): Promise<void>;

  /**
   * Установить новый код для открытия хранилища.
   * @param code
   * @param options
   * @exception RNSecurityError
   */
  setUnlockCode(code: string, options?: {}): Promise<void>;

  /**
   * Запросить биометрию для открытия хранилища.
   * @param options
   */
  setUnlockBiometry(options?: {}): Promise<void>;

  /**
   * Отменить операцию, связанную с биоиетрией: setUnlockBiometry или unlockByBiometry.
   * @param options
   */
  cancelBiometry(options?: {}): Promise<void>;

  /***
   * Сохранить данные в хранилище. Хранилище должно быть открыто при помощи unlockByCode или unlockByBiometry.
   * @param creds
   * @param options
   * @exception RNSecurityError
   */
  save(creds: string | undefined, options?: {}): Promise<void>;

  /**
   * Прочитать данные из хранилища. Хранилище должно быть открыто при помощи unlockByCode или unlockByBiometry.
   * @param options
   * @exception RNSecurityError
   */
  read(options?: {}): Promise<string | undefined>;

  /**
   * Закрыть хранилище. Для открытия необходимо использовать unlockByCode или unlockByBiometry.
   * @param options
   * @exception RNSecurityError
   */
  lock(options?: {}): Promise<void>;

  /**
   * Очистить хранилище от всех данных.
   * @param options
   * @exception RNSecurityError
   */
  clean(options?: {}): Promise<void>;

  /**
   * Проверить, изменились ли биометрические данные.
   * @exception RNException
   */
  hasFingerPrintChanged(): Promise<boolean>

  /**
   * Инициализация модуля (очистка не валидных данных).
   * @param options
   * @exception RNSecurityError
   */
  initialSetup(options?: {}): Promise<void>;
}
