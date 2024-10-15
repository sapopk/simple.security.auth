package simple.security.auth.Entity;

import jakarta.persistence.Entity;
import jakarta.persistence.Table;
import jakarta.persistence.Id;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Column;
import org.springframework.security.core.GrantedAuthority;

@Entity
@Table(name = "role")
public class RoleEntity implements GrantedAuthority {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "role_id")
    private Long roleId;
    @Column(name = "role_authority")
    private String authority;

    public RoleEntity() {}

    public RoleEntity(String authority) {
        this.authority = authority;
    }

    public RoleEntity(Long id, String authority) {
        this.roleId = id;
        this.authority = authority;
    }

    public Long getRoleID() {
        return this.roleId;
    }

    @Override
    public String getAuthority() {
        return this.authority;
    }

    public void setRoleID(Long id) {
        this.roleId = id;
    }

    public void setAuthority(String auth) {
        this.authority = auth;
    }
}
