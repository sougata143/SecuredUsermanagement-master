package com.easybusiness.usermanagement.repository.CustomRepository;

import java.util.List;

import com.easybusiness.usermanagement.entity.RoleActionMap;

public interface RoleActionMapCustomRepository {

    RoleActionMap getRoleActionMapById(Long mappingId);

    void deleteRoleActionMap(Long mappingId);

    void updateRoleActionMap(RoleActionMap roleActionMap);

    void addRoleActionMap(RoleActionMap roleActionMap);

    List<RoleActionMap> getAllRoleActionMaps();

}
