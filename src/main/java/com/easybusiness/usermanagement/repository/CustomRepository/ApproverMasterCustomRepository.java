package com.easybusiness.usermanagement.repository.CustomRepository;

import java.util.List;

import com.easybusiness.usermanagement.entity.ApproverMaster;

public interface ApproverMasterCustomRepository {

    ApproverMaster getApproverMasterById(Long mappingId);

    void deleteApproverMaster(Long mappingId);

    void updateApproverMaster(ApproverMaster approverMaster);

    void addApproverMaster(ApproverMaster approverMaster);

    List<ApproverMaster> getAllApproverMasters();

}
