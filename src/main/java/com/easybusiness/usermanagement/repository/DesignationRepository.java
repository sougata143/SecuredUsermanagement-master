package com.easybusiness.usermanagement.repository;

import java.util.List;
import java.util.Optional;

import org.springframework.data.repository.CrudRepository;

import com.easybusiness.usermanagement.entity.Designation;
import com.easybusiness.usermanagement.repository.CustomRepository.DesignationCustomRepository;

public interface DesignationRepository extends CrudRepository<Designation, Long>, DesignationCustomRepository {

    Optional<Designation> findById(Long i);

    List<Designation> findByDesig(String desigName);

}
