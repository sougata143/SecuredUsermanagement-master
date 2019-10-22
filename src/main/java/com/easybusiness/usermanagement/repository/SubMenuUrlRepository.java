package com.easybusiness.usermanagement.repository;

import java.util.List;
import java.util.Optional;

import org.springframework.data.repository.CrudRepository;

import com.easybusiness.usermanagement.entity.SubMenu;
import com.easybusiness.usermanagement.entity.SubMenuUrl;
import com.easybusiness.usermanagement.repository.CustomRepository.SubMenuUrlCustomRepository;

public interface SubMenuUrlRepository extends CrudRepository<SubMenuUrl, Long>, SubMenuUrlCustomRepository {

    Optional<SubMenuUrl> findById(Long i);

    List<SubMenuUrl> findBySubMenu(SubMenu subMenu);

}
