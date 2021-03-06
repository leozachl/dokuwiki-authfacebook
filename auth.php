<?php
/**
 * Facebook authentication backend
 * derived from Václav Voborníks FBauth and sentryperm@gmail.coms authgoogle
 *
 * @license    GPL 2 (http://www.gnu.org/licenses/gpl.html)
 * @author     Leo Zachl <leo.zachl@gmail.com>
 */

define('DOKU_AUTH', dirname(__FILE__));
// require_once(DOKU_AUTH.'/basic.class.php');
require_once(DOKU_AUTH.'/lib/autoload.php');
require_once(DOKU_AUTH.'/dwPersistentData.php');

// define cookie and session id, append server port when securecookie is configured
if (!defined('AUTHFACEBOOK_COOKIE')) define('AUTHFACEBOOK_COOKIE', 'SPFB'.md5(DOKU_REL.(($conf['securecookie'])?$_SERVER['SERVER_PORT']:'')));

#define('AUTH_USERFILE',DOKU_CONF.'users.auth.php');

class auth_plugin_authfacebook extends auth_plugin_authplain {

  var $users = null;
  var $_pattern = array();

  var $fbsession = array();

  public function __construct() {
    global $conf, $config_cascade;

    parent::__construct();

    $this->cando['external'] = true;
    $this->cando['logout']   = true;
    $this->cando['delUser']   = false;

    $this->success = true;
    return;

  }

  function trustExternal($user,$pass,$sticky=true ){
    global $USERINFO;
    global $conf;
    $sticky ? $sticky = true : $sticky = false; //sanity check

    if (!empty($_SESSION[DOKU_COOKIE]['authfacebook']['user'])) {
      $USERINFO = $_SESSION[DOKU_COOKIE]['authfacebook']['info'];
      if (!$USERINFO['is_facebook']){
        $this->cando['modPass'] = true;
        $this->cando['delUser'] = true;
      }
      $_SERVER['REMOTE_USER'] = $_SESSION[DOKU_COOKIE]['authfacebook']['user'];
      return true;
    }

    //get authplain form login info
    if(!empty($user)){
      if($this->checkPass($user,$pass)){
        $uinfo  = $this->getUserData($user);

        //set user info
        $USERINFO['name'] = $uinfo['name'];
        $USERINFO['mail'] = $uinfo['mail'];
        $USERINFO['grps'] = $uinfo['grps'];
        $USERINFO['is_facebook'] = false;
        $USERINFO['pass'] = ''; // $pass;

        //save data in session
        $_SERVER['REMOTE_USER'] = $uinfo['name'];
        $_SESSION[DOKU_COOKIE]['authfacebook']['user'] = $user;
        $_SESSION[DOKU_COOKIE]['authfacebook']['info'] = $USERINFO;
        return true;
      } else {
        //invalid credentials - log off
        msg($this->getLang('badlogin'),-1);
        return false;
      }
    }

    if ($_COOKIE[AUTHFACEBOOK_COOKIE]) {
      $_SESSION[DOKU_COOKIE]['authfacebook']['token'] = $_COOKIE[AUTHFACEBOOK_COOKIE];
    }

    if (($appId = $this->getConf('applicationID')) && ($appSecret = $this->getConf('applicationSecret'))) {
      $fb = new Facebook\Facebook(array(
        'app_id'      => $appId,
        'app_secret'     => $appSecret,
        'default_graph_version' => 'v2.12',
        'persistent_data_handler'     => new MyDokuWikiPersistentDataHandler(),
      ));
      $helper = $fb->getRedirectLoginHelper();

      if (isset($_GET['code'])) {
        //get token
        try {
          $accessToken = $helper->getAccessToken();
          if ($accessToken) {
            //save token in session
            $_SESSION[DOKU_COOKIE]['authfacebook']['token'] = $accessToken;
            //save token in cookies
            $this->_updateCookie($_SESSION[DOKU_COOKIE]['authfacebook']['token'], time() + 60 * 60 * 24 * 365);
            try {
              $response = $fb->get('/me?fields=id,name,email', $accessToken);
            } catch (FacebookApiException $e) {
              error_log("2: " . $e);
            }
            if ($response) {
              $me = $response->getGraphUser();

              // the FB-App is only allowed to read the groups of the App-Admin
              $response = $fb->get('/me/permissions', $accessToken);
              $permissions = $response->getGraphEdge();
              if ($me['id'] == $this->getConf('appAdmin'))
                $this->getFacebookGroups($fb, $permissions, $accessToken);

              $grantedpermissions = array();
              foreach($permissions as $permission)
                if ($permission['status'] == 'granted')
                  $grantedpermissions[] = $permission['permission'];
              $_SESSION[DOKU_COOKIE]['authfacebook']['permissions'] = $grantedpermissions;

              $USERINFO['name'] = $me['name'];
              $USERINFO['mail'] = $me['email'];
              $USERINFO['is_facebook'] = true;
              $USERINFO['grps'] = array( $this->getConf('defaultgroup'));
              if (($fbgroupid = $this->getConf('fbgid2group')) != ''){
                if ($fbg2user = json_decode($fbgroupid,TRUE)){
                  require(DOKU_CONF.'/fb_groups.php');
                  foreach($fbg2user as $id => $group){
                    if (isset($fb_groups[$id]) && isset($fb_groups[$id][$me['id']])) $USERINFO['grps'][] = $group;
                  }
                }
              }
              if (in_array($me['id'],json_decode($this->getConf('superuser'))))
                $USERINFO['grps'][] = 'admin';

              touch(DOKU_CONF.'/fb_ids.php');
              $fb_ids_fd = fopen(DOKU_CONF.'/fb_ids.php','r+');
              $fb_ids_lock = flock($fb_ids_fd, LOCK_EX | LOCK_NB);
              require(DOKU_CONF.'/fb_ids.php');

              if (isset($fb_ids[$me['id']])){
                $user = $fb_ids[$me['id']];
              } else {
                $plain_user = $this->retrieveUsers(0,0,array('mail' => '^'.$me['email'].'$'));
                if (count($plain_user) > 0)
                  $user = reset(array_keys($plain_user));
                else { 
                  if (!empty($me['email']))
                    $user = strtolower(reset(explode('@',$me['email'])));
                  else
                    $user = preg_replace("/[^a-z0-9]/","_",strtolower(trim(basename(stripslashes(iconv("utf8","ascii//translit",strtr($me['name'],' ','.')))), ".\x00..\x20")));
                  $plain_user = $this->retrieveUsers(0,0,array('user' => '^'.$user.'$'));
                  $ext = ''; $cnt=0;
                  while (count($plain_user) > 0 || in_array($user.$ext,$fb_ids)){
                    $cnt++;
                    $ext = '-'.$cnt;
                    $plain_user = $this->retrieveUsers(0,0,array('user' => '^'.$user.$ext.'$'));
                  }
                  $user = $user.$ext;
                  $fb_ids[$me['id']] = $user;
                  if ($fb_ids_lock){
                    ftruncate($fb_ids_fd, 0); // kürze Datei
                    fwrite($fb_ids_fd,"<?php\n\$fb_ids = ".var_export($fb_ids,true).";\n");
                    fflush($fb_ids_fd);
                  }
                }
              }
              flock($fb_ids_fd, LOCK_UN);
              fclose($fb_ids_fd);

              $_SESSION[DOKU_COOKIE]['authfacebook']['userid'] = $me['id'];
              $_SERVER['REMOTE_USER'] = $user;
              $_SESSION[DOKU_COOKIE]['authfacebook']['user'] = $user;
              $_SESSION[DOKU_COOKIE]['authfacebook']['pass'] = '';
              $_SESSION[DOKU_COOKIE]['authfacebook']['info'] = $USERINFO;

              //redirect to login page
              header("Location: ".wl('start', array(), true, '&'));
              die();

            } //me
          } else { // FB session 
            $_SESSION[DOKU_COOKIE]['authfacebook']['auth_url'] = $helper->getLoginUrl(
              wl('start',array('do'=>'login'),true, '&'),
              explode(',',$this->getConf('scope'))
            );
          }
        } catch (Exception $e) {
          $_SESSION[DOKU_COOKIE]['authfacebook']['auth_url'] = $helper->getLoginUrl(
            wl('start',array('do'=>'login'),true, '&'),
            explode(',',$this->getConf('scope'))
          );
          msg('1: Auth Facebook Error: '. $e->getFile() .':'.$e->getLine().': '.$e->getMessage());
        }
      }

      if (!isset($_SESSION[DOKU_COOKIE]['authfacebook']['auth_url']))
      $_SESSION[DOKU_COOKIE]['authfacebook']['auth_url'] = $helper->getLoginUrl(
        wl('start',array('do'=>'login'),true, '&'),
        explode(',',$this->getConf('scope'))
      );
    }

    return false;
  }

  function logOff(){
    unset($_SESSION[DOKU_COOKIE]['authfacebook']['token']);
    unset($_SESSION[DOKU_COOKIE]['authfacebook']['user']);
    unset($_SESSION[DOKU_COOKIE]['authfacebook']['info']);
    unset($_SESSION[DOKU_COOKIE]['authfacebook']['userid']);
    // clear the cookie
    $this->_updateCookie('', time() - 600000);
    if (($appId = $this->getConf('applicationID')) && ($appSecret = $this->getConf('applicationSecret'))) {
        $fb = new Facebook\Facebook(array(
            'app_id' => $appId,
            'app_secret' => $appSecret,
            'default_graph_version' => 'v2.3',
            'persistent_data_handler'     => new MyDokuWikiPersistentDataHandler(),
        ));
    }
    unset($_SESSION[DOKU_COOKIE]['authfacebook']['auth_url']);
  }

  function _updateCookie($value, $time) {
    global $conf;

    $cookieDir = empty($conf['cookiedir']) ? DOKU_REL : $conf['cookiedir'];
    if (version_compare(PHP_VERSION, '5.2.0', '>')) {
      setcookie(AUTHFACEBOOK_COOKIE, $value, $time, $cookieDir, '', ($conf['securecookie'] && is_ssl()), true);
    } else {
      setcookie(AUTHFACEBOOK_COOKIE, $value, $time, $cookieDir, '', ($conf['securecookie'] && is_ssl()));
    }
  }

  private function getFacebookGroups($facebook,$permissions, $accessToken){
    if ($mapgroups = json_decode($this->getConf('fbgid2group'),true)){
      foreach($permissions as $permission){
        if ($permission['permission'] == 'user_managed_groups' && $permission['status'] == 'granted'){
          $groups = $facebook->get('/me/groups', $accessToken);
          $groups = $groups->getGraphEdge();
          $usergroups = array();
          foreach($groups as $group){
            $usergroups[$group['id']] = $group['name'];
          }
          if (is_file(DOKU_CONF.'/fb_groups_orig.php'))
            include(DOKU_CONF.'/fb_groups_orig.php');
          else
            $fb_groups = array();
          foreach(array_intersect_key($mapgroups,$usergroups) as $groupid => $groupname){
            $group_members = $facebook->get('/'.$groupid.'/members', $accessToken);
            if (!empty($group_members))
              foreach($group_members as $member)
                $fb_groups[$groupid][$member['id']] = $member['name'];

          }
          if (!empty($this->getConf('saveAccessKey'))){
            $token = "\$fb_token = '".$accessToken."';\n";
          } else {
            $token;
          }
          file_put_contents(DOKU_CONF.'/fb_groups.php',"<?php\n\$fb_groups = ".var_export($fb_groups,true).";\n".$token);
        }
      }
    }
  }

}

//Setup VIM: ex: et ts=2 enc=utf-8 :
