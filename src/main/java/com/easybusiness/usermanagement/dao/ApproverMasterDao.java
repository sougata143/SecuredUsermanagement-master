package com.easybusiness.usermanagement.dao;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import javax.sql.DataSource;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import com.easybusiness.usermanagement.entity.ApproverMaster;
import com.easybusiness.usermanagement.entity.User;
import com.easybusiness.usermanagement.repository.ApproverMasterRepository;
import com.easybusiness.usermanagement.repository.ApproverMasterSpecifications;


/*
 * DAO class for APPROVER_MASTER table
 */
@Component
public class ApproverMasterDao {
    private static final Logger LOGGER = LoggerFactory.getLogger(ApproverMasterDao.class);
    @Autowired
    DataSource dataSource;

    @Autowired
    ApproverMasterRepository approverMasterRepository;
    
    @Autowired
    UserDao userDao;

	

    /*
     * find all method for finding all the datas from APPROVER_MASTER table
     */
    @Transactional(readOnly = true)
    public List<ApproverMaster> findAll() throws Exception {
	LOGGER.info("DATASOURCE = " + dataSource);
	List<ApproverMaster> approverMasterList = new ArrayList<ApproverMaster>();
	for (ApproverMaster approverMaster : approverMasterRepository.findAll()) {
	    LOGGER.info("ApproverMaster : " + approverMaster);
	    approverMasterList.add(approverMaster);

	}
	return approverMasterList;

    }

    /*
     * find by id method for finding data by taskid from APPROVER_MASTER table
     */
    @Transactional(readOnly = true)
    public Optional<ApproverMaster> findByTaskId(Long taskId) {

	return approverMasterRepository.findById(taskId);
    }

    
    /*
     * findByTaskDesc method for fetching data by taskdesc from APPROVER_MASTER table
     */
    @Transactional(readOnly = true)
    public ApproverMaster findApproverMasterByTaskDesc(String taskDesc) {

	return approverMasterRepository.findByTaskDesc(taskDesc).get(0);
    }
    
    
    /*
     * this method first finds user by calling findUserById method of userDao class and then use the result to
     * find approver authorities by calling ApproverMasterSpecifications class inside approverMasterRepository
     * findAll method
     */
    @Transactional(readOnly = true)
    public List<ApproverMaster> findApproverAuthoritiesOfUser(String userId) {

	User user=userDao.findUserById(Long.parseLong(userId));
	System.out.println(user);
	System.out.println(ApproverMasterSpecifications.findIfUserIsAnyApprover(user));
	return approverMasterRepository.findAll(ApproverMasterSpecifications.findIfUserIsAnyApprover(user));
    }
    
   /* @Transactional(readOnly = true)
    public List<ApproverMaster> findApproverAuthoritiesOfUser(String userId) {

	User users=userDao.findUserById(Long.parseLong(userId));
	return approverMasterRepository.findByUser(users.getId());
    }*/
    
    
    /*
     * checking whether the user is approver for the task or not
     */
    @Transactional(readOnly = true)
    public Boolean findIfUserIsApproverForTaskId(String userId,String taskId) {

	try{
	User user=userDao.findUserById(Long.parseLong(userId));
	List<ApproverMaster> approverListForATask=approverMasterRepository.findAll(ApproverMasterSpecifications.findIfUserIsAnyApproverOfParticularTask(user, taskId));
	return (approverListForATask.size()>0);
	}
	catch(Exception e)
	{
	    LOGGER.error("exception while findIfUserIsApproverForTaskId for user Id{},task Id{} is {}",userId,taskId,e.getMessage() );
	    return false;
	}
    }

    
    /*
     * saving approvermaster to the database by calling addApproverMaster method of approverMasterrepository
     */
    @Transactional(propagation = Propagation.REQUIRED)
    public void addApproverMaster(ApproverMaster approverMaster) {
	approverMasterRepository.addApproverMaster(approverMaster);
	LOGGER.info("ApproverMaster added successfully " + approverMaster.toString());
    }

    
    /*
     * deleting approvermaster data from database by calling delete method 
     */
    @Transactional(propagation = Propagation.REQUIRED)
    public void deleteApproverMaster(Long approverMasterId) {
	approverMasterRepository.deleteApproverMaster(approverMasterId);
	LOGGER.info("ApproverMaster with id " + approverMasterId + " deleted successfully ");
    }

}
