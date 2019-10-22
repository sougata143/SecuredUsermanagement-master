package com.easybusiness.usermanagement.repository;

import java.util.List;
import java.util.Optional;

import org.springframework.data.repository.CrudRepository;

import com.easybusiness.usermanagement.entity.Organization;
import com.easybusiness.usermanagement.repository.CustomRepository.OrganizationCustomRepository;

public interface OrganizationRepository extends CrudRepository<Organization, Long>, OrganizationCustomRepository {

    Optional<Organization> findById(Long i);

    List<Organization> findByOrgName(String organizationName);

}
