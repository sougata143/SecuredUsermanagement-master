package com.easybusiness.usermanagement.repository.CustomRepository;

import java.util.List;

import com.easybusiness.usermanagement.entity.Role;

public interface RoleCustomRepository {

    Role getRoleById(Long roleId);

    boolean roleExists(String roleDesc, String roleName);

    void deleteRole(Long roleId);

    void updateRole(Role role);

    void addRole(Role role);

    List<Role> getAllRoles();

}
