package com.easybusiness.usermanagement.repository.CustomRepository;

import java.util.List;

import com.easybusiness.usermanagement.entity.UserGroup;

public interface UserGroupCustomRepository {

    UserGroup getUserGroupById(Long id);

    void deleteUserGroup(Long usergroupId);

    void updateUserGroup(UserGroup userGroup);

    void addUserGroup(UserGroup userGroup);

    List<UserGroup> getAllUserGroups();
    
    boolean isUserGroupExist(long id, String userGroupName);

}
