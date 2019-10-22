package com.easybusiness.usermanagement.repository;

import java.util.List;
import java.util.Optional;

import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.CrudRepository;
import org.springframework.web.bind.annotation.PathVariable;

import com.easybusiness.usermanagement.entity.ApproverMaster;
import com.easybusiness.usermanagement.repository.CustomRepository.ApproverMasterCustomRepository;

public interface ApproverMasterRepository extends CrudRepository<ApproverMaster, Long>, ApproverMasterCustomRepository,JpaSpecificationExecutor<ApproverMaster> {

    Optional<ApproverMaster> findById(Long id);

    List<ApproverMaster> findByTaskDesc(String taskDesc);

    List<ApproverMaster> findAll();
    
    @Query("select a from ApproverMaster a where a.user1.id = :userId or a.user2.id = :userId or a.user3.id = :userId or a.user4.id = :userId or a.user5.id = :userId")
    List<ApproverMaster> findByUser(@PathVariable("userid") long userid);

}
