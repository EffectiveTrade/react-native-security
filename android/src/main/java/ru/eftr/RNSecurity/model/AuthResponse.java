package ru.eftr.RNSecurity.model;

/**
 * Created by Kashanov Ivan on 20.02.18.
 */

public class AuthResponse extends Object{
    String code;
    String login;
    String password;

    public AuthResponse(){
        this(ErrorCode.NONE.getCode());
    }

    public AuthResponse(String code){
        this(code, "", "");
    }

    public AuthResponse(String code, String login, String password){
        setCode(code);
        setLogin(login);
        setPassword(password);
    }

    public String getCode() {
        return code;
    }

    public void setCode(String errorCode) {
        this.code = errorCode;
    }

    public String getLogin() {
        return login;
    }

    public void setLogin(String login) {
        this.login = login;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }
}
