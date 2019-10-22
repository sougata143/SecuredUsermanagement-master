package com.easybusiness.usermanagement.repository.CustomRepository;

import java.util.List;

import com.easybusiness.usermanagement.entity.SubMenu;

public interface SubMenuCustomRepository {

    SubMenu getSubMenuById(Long menuId);

    void deleteSubMenu(Long MenuId);

    void updateSubMenu(SubMenu subMenu);

    void addSubMenu(SubMenu subMenu);

    List<SubMenu> getAllSubMenus();

}
