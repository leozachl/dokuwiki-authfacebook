<?php

use Facebook\PersistentData\PersistentDataInterface;

class MyDokuWikiPersistentDataHandler implements PersistentDataInterface
{
  /**
   * @var string Prefix to use for session variables.
   */
  protected $sessionPrefix = 'FBRLH_';

  /**
   * @inheritdoc
   */
  public function get($key)
  {
    trigger_error($key. ". ". $_SESSION[DOKU_COOKIE][$this->sessionPrefix . $key]);
    return $_SESSION[DOKU_COOKIE][$this->sessionPrefix . $key];
  }

  /**
   * @inheritdoc
   */
  public function set($key, $value)
  {
    $_SESSION[DOKU_COOKIE][$this->sessionPrefix . $key] = $value;
  }
}
