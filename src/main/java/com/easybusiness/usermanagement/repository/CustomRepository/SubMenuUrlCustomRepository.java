package com.easybusiness.usermanagement.repository.CustomRepository;

import java.util.List;

import com.easybusiness.usermanagement.entity.SubMenuUrl;

public interface SubMenuUrlCustomRepository {

    SubMenuUrl getSubMenuUrlById(Long menuId);

    void deleteSubMenuUrl(Long MenuId);

    void updateSubMenuUrl(SubMenuUrl subMenu);

    void addSubMenuUrl(SubMenuUrl subMenu);

    List<SubMenuUrl> getAllSubMenuUrls();

}
