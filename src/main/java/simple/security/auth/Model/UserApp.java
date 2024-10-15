package simple.security.auth.Model;

public class UserApp {
    private String username;
    private String password;

    public UserApp(String name, String pwd) {
        this.username = name;
        this.password = pwd;
    }

    public String getUsername() {
        return this.username;
    }

    public String getPassword() {
        return this.password;
    }

    public void setUsername(String name) {
        this.username = name;
    }

    public void setPassword(String pwd) {
        this.password = pwd;
    }
}
