package com.easybusiness.usermanagement.repository;

import java.util.List;

import org.springframework.data.repository.CrudRepository;

import com.easybusiness.usermanagement.entity.Bank;
import com.easybusiness.usermanagement.entity.Branch;
import com.easybusiness.usermanagement.repository.CustomRepository.BranchCustomRepository;

public interface BranchRepository extends CrudRepository<Branch, Long>, BranchCustomRepository {

    List<Branch> findById(long id);

    List<Branch> findByBank(Bank bank);

}
