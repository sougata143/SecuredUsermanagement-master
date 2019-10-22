package com.easybusiness.usermanagement.repository;

import java.util.List;
import java.util.Optional;

import org.springframework.data.repository.CrudRepository;

import com.easybusiness.usermanagement.entity.Department;
import com.easybusiness.usermanagement.entity.Organization;
import com.easybusiness.usermanagement.repository.CustomRepository.DepartmentCustomRepository;

public interface DepartmentRepository extends CrudRepository<Department, Long>, DepartmentCustomRepository {

    Optional<Department> findById(Long i);

    List<Department> findByOrganization(Optional<Organization> organization);
    
    List<Department> findByDeptName(String deptName);

}
