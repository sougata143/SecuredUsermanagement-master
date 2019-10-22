package com.easybusiness.usermanagement.repository.CustomRepository;

import java.util.List;

import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import com.easybusiness.usermanagement.entity.UserGroupMenuSubMenu;

public interface UserGroupMenuSubMenuCustomRepository {

    UserGroupMenuSubMenu getUserGroupMenuById(Long id);

    @Query("update UserGroupMenuSubMenu set isEnable = 0 where id = :id")
    void deleteUserGroupMenu(@Param("id") Long id);

    void updateUserGroupMenu(UserGroupMenuSubMenu userGroupMenu);

    void addUserGroupMenu(UserGroupMenuSubMenu userGroupMenu);

    List<UserGroupMenuSubMenu> getAllUserGroupMenus();

}
