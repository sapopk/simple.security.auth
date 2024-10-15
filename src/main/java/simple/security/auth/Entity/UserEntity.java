package simple.security.auth.Entity;

import jakarta.persistence.*;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.HashSet;
import java.util.Set;


@Entity
@Table(name = "user")
public class UserEntity implements UserDetails {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "user_id")
    private Long userID;
    @Column(name = "user_name", unique = true)
    private String username;
    @Column(name = "user_password")
    private String password;

    @ManyToMany(fetch = FetchType.EAGER)
    @JoinTable(
            name = "user_role_jun",
            joinColumns = {@JoinColumn(name = "user_id")},
            inverseJoinColumns = {@JoinColumn(name = "role_id")}
    )
    private Set<RoleEntity> authorities;

    public UserEntity() {
        this.authorities = new HashSet<>();
    }

    public UserEntity(String name, String pwd, Set<RoleEntity> auth) {
        this.username = name;
        this.password = pwd;
        this.authorities = auth;
    }

    public Long getUserID() {
        return this.userID;
    }

    @Override
    public String getUsername() {
        return this.username;
    }

    @Override
    public String getPassword() {
        return this.password;
    }

    @Override
    public Set<RoleEntity> getAuthorities() {
        return this.authorities;
    }

    public void setUserID(Long id) {
        this.userID = id;
    }

    public void setUsername(String name) {
        this.username = name;
    }

    public void setPassword(String pwd) {
        this.password = pwd;
    }

    public void setAuthorities(Set<RoleEntity> auth) {
        this.authorities = auth;
    }
}
