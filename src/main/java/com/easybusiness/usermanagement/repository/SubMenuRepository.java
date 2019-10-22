package com.easybusiness.usermanagement.repository;

import java.util.List;
import java.util.Optional;

import org.springframework.data.repository.CrudRepository;

import com.easybusiness.usermanagement.entity.Menu;
import com.easybusiness.usermanagement.entity.SubMenu;
import com.easybusiness.usermanagement.repository.CustomRepository.SubMenuCustomRepository;

public interface SubMenuRepository extends CrudRepository<SubMenu, Long>, SubMenuCustomRepository {

    Optional<SubMenu> findById(Long i);

    List<SubMenu> findByMenu(Menu menu);

}
