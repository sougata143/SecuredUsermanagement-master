package com.easybusiness.usermanagement.repository.CustomRepository;

import java.util.List;

import com.easybusiness.usermanagement.entity.UserRoleMap;

public interface UserRoleMapCustomRepository {

    UserRoleMap getUserRoleMapById(Long mappingId);

    void deleteUserRoleMap(Long mappingId);

    void updateUserRoleMap(UserRoleMap userRoleMap);

    void addUserRoleMap(UserRoleMap userRoleMap);

    List<UserRoleMap> getAllUserRoleMaps();

}
