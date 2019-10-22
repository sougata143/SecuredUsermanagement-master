package com.easybusiness.usermanagement.services.serviceimpl;

import static com.easybusiness.usermanagement.constant.UserManagementConstant.USER_HOST_SERVER;

import java.util.ArrayList;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import com.easybusiness.usermanagement.DTO.ApproverMasterDTO;
import com.easybusiness.usermanagement.DTO.DepartmentDto;
import com.easybusiness.usermanagement.DTO.DesignationDto;
import com.easybusiness.usermanagement.DTO.LocationMasterDTO;
import com.easybusiness.usermanagement.DTO.OrganizationDto;
import com.easybusiness.usermanagement.DTO.UserDTO;
import com.easybusiness.usermanagement.dao.ApproverMasterDao;
import com.easybusiness.usermanagement.dao.UserDao;
import com.easybusiness.usermanagement.entity.ApproverMaster;
import com.easybusiness.usermanagement.entity.Department;
import com.easybusiness.usermanagement.entity.Designation;
import com.easybusiness.usermanagement.entity.LocationMaster;
import com.easybusiness.usermanagement.entity.Organization;
import com.easybusiness.usermanagement.entity.User;
import com.easybusiness.usermanagement.services.ApproverMasterService;


/*
 * Service and RestController class for APPROVER_MASTER
 */
@RestController
@RequestMapping("/easybusiness/approverflow/")
public class ApproverMasterServiceImpl implements ApproverMasterService {

    @Autowired
    UserDao userDao;

    @Autowired
    ApproverMasterDao approverMasterDao;
    
    private static final Logger LOGGER=LoggerFactory.getLogger(ApproverMasterServiceImpl.class);

    
    /*
     * (non-Javadoc)
     * @see com.easybusiness.usermanagement.services.approvermaster.ApproverMasterService#getApproverListByTaskId(java.lang.String)
     * fetching approvermaster by taskid
     * GET method for APPROVER_MASTER table with param taskid
     */
    @Override
    @CrossOrigin(origins = USER_HOST_SERVER)
    @RequestMapping(value = "getApproverMasterByTaskId/{taskid}", method = RequestMethod.GET)
    @ResponseBody
    public ResponseEntity<List<ApproverMasterDTO>> getApproverListByTaskId(@PathVariable("taskid") String taskId) {

	List<ApproverMaster> approverMasterEntityList = (List<ApproverMaster>) approverMasterDao.findByTaskId(Long.parseLong(taskId)).get();
	List<ApproverMasterDTO> approverMasterDtoList = new ArrayList<ApproverMasterDTO>();
	approverMasterEntityList.forEach(approverMasterEntity -> {

	    ApproverMasterDTO approverMasterDTO = new ApproverMasterDTO();
	    approverMasterDTO = prepareApproverMasterDTO(approverMasterEntity);
	    approverMasterDtoList.add(approverMasterDTO);
	});

	return new ResponseEntity<List<ApproverMasterDTO>>(approverMasterDtoList, HttpStatus.OK);

    }

    /*
     * (non-Javadoc)
     * @see com.easybusiness.usermanagement.services.approvermaster.ApproverMasterService#getApproverListByTaskDesc(java.lang.String)
     * fetching approvermaster by taskdesc
     * GET method for APPROVER_MASTER table with param taskdesc
     */
    @Override
    @CrossOrigin(origins = USER_HOST_SERVER)
    @RequestMapping(value = "getApproverMasterByTaskDesc/{taskdesc}", method = RequestMethod.GET)
    @ResponseBody
    public ResponseEntity<ApproverMasterDTO> getApproverListByTaskDesc(@PathVariable("taskdesc") String taskDesc) {

	ApproverMaster approverMasterEntity = approverMasterDao.findApproverMasterByTaskDesc(taskDesc);
	ApproverMasterDTO approverMasterDto = prepareApproverMasterDTO(approverMasterEntity);
	return new ResponseEntity<ApproverMasterDTO>(approverMasterDto, HttpStatus.OK);

    }

    
    /*
     * (non-Javadoc)
     * @see com.easybusiness.usermanagement.services.approvermaster.ApproverMasterService#findApproverAuthoritiesOfUser(java.lang.String)
     * fetching Approvermaster by userId
     * GET method for APPROVER_MASTER table with param userId
     */
    @Override
    @CrossOrigin(origins = USER_HOST_SERVER)
    @RequestMapping(value = "findApproverAuthoritiesOfUser/{userId}", method = RequestMethod.GET)
    @ResponseBody
    public List<ApproverMasterDTO> findApproverAuthoritiesOfUser(@PathVariable("userId") String userId) {

	List<ApproverMaster> approverMasterEntityList = approverMasterDao.findApproverAuthoritiesOfUser(userId);
	List<ApproverMasterDTO> approverMasterDtoList = new ArrayList<ApproverMasterDTO>();
	approverMasterEntityList.forEach(approverMasterEntity -> {

	    ApproverMasterDTO approverMasterDTO = new ApproverMasterDTO();
	    approverMasterDTO = prepareApproverMasterDTO(approverMasterEntity);
	    approverMasterDtoList.add(approverMasterDTO);
	});

	return approverMasterDtoList;
    }

    
    /*
     * (non-Javadoc)
     * @see com.easybusiness.usermanagement.services.approvermaster.ApproverMasterService#getAllDetailsOfApproverMaster()
     * fetching all approvermaster details
     * GET method for APPROVER_MASTER table 
     */
    @Override
    @CrossOrigin(origins = USER_HOST_SERVER)
    @RequestMapping(value = "findAllDetailsOfApproverMaster", method = RequestMethod.GET)
    @ResponseBody
    public List<ApproverMasterDTO> getAllDetailsOfApproverMaster() {

	List<ApproverMaster> approverMasterEntityList = new ArrayList<ApproverMaster>();
	try {
	    approverMasterEntityList = approverMasterDao.findAll();
	} catch (Exception e) {
	    // TODO Auto-generated catch block
	    e.printStackTrace();
	}
	List<ApproverMasterDTO> approverMasterDtoList = new ArrayList<ApproverMasterDTO>();
	approverMasterEntityList.forEach(approverMasterEntity -> {

	    ApproverMasterDTO approverMasterDTO = new ApproverMasterDTO();
	    approverMasterDTO = prepareApproverMasterDTO(approverMasterEntity);
	    approverMasterDtoList.add(approverMasterDTO);
	});

	return approverMasterDtoList;
    }

    
    /*
     * (non-Javadoc)
     * @see com.easybusiness.usermanagement.services.approvermaster.ApproverMasterService#findIfUserIsApproverForTaskId(java.lang.String, java.lang.String)
     * checking wheter the user is approver for the task or not
     * GET method for APPROVER_MASTER table with params userID and taskid
     */
    @Override
    @CrossOrigin(origins = USER_HOST_SERVER)
    @RequestMapping(value = "findIfUserIsApproverForTaskId/{userId}/{taskid}", method = RequestMethod.GET)
    @ResponseBody
    public Boolean findIfUserIsApproverForTaskId(@PathVariable("userId") String userId,
	    @PathVariable("taskid") String taskId) {

	try{
	return approverMasterDao.findIfUserIsApproverForTaskId(userId, taskId);
	}
	catch(Exception e)
	{
	    LOGGER.error("exception while findIfUserIsApproverForTaskId for user Id{},task Id{} is {}",userId,taskId,e.getMessage() );
	    return false;
	}
    }

    
    /*
     * (non-Javadoc)
     * @see com.easybusiness.usermanagement.services.approvermaster.ApproverMasterService#persistApproveMaster(com.easybusiness.usermanagement.DTO.ApproverMasterDTO)
     * saving approvermaster to database
     * POST method for APPROVER_MASTER table with ApproverMasterDTO request body
     */
    @Override
    @CrossOrigin(origins = USER_HOST_SERVER)
    @RequestMapping(value = "addUpdateApproveMaster", method = RequestMethod.POST)
    @ResponseBody
    public ResponseEntity<ApproverMasterDTO> persistApproveMaster(@RequestBody ApproverMasterDTO approverMasterDTO) {

	ApproverMaster approverMasterEntity = prepareApproverMasterEntity(approverMasterDTO);

	approverMasterDao.addApproverMaster(approverMasterEntity);
	return new ResponseEntity<ApproverMasterDTO>(approverMasterDTO, HttpStatus.CREATED);

    }

    
    /*
     * preparing ApproverMasterEntity from ApproverMasterDTO
     */
    private ApproverMaster prepareApproverMasterEntity(ApproverMasterDTO approverMasterDTO) {
	ApproverMaster approverMaster = new ApproverMaster();
	approverMaster.setModifiedBy(approverMasterDTO.getModifiedBy());
	approverMaster.setModifiedOn(approverMasterDTO.getModifiedOn());
	approverMaster.setTaskDesc(approverMasterDTO.getTaskDesc());
	approverMaster.setUser1(prepareUserEntity(approverMasterDTO.getUser1()));
	approverMaster.setUser2(prepareUserEntity(approverMasterDTO.getUser2()));
	approverMaster.setUser3(prepareUserEntity(approverMasterDTO.getUser3()));
	approverMaster.setUser4(prepareUserEntity(approverMasterDTO.getUser4()));
	approverMaster.setUser5(prepareUserEntity(approverMasterDTO.getUser5()));
	if (null != getApproverListByTaskDesc(approverMasterDTO.getTaskDesc())) {
	    approverMaster.setId(getApproverListByTaskDesc(approverMasterDTO.getTaskDesc()).getBody().getId());
	}
	return approverMaster;
    }

    
    /*
     * preparing UserEntity from UserDTO
     */
    private User prepareUserEntity(UserDTO userDTO) {
	User userEntity = new User();
	userEntity.setAlternateEmail(userDTO.getAlternateEmail());
	userEntity.setDateOfBirth(userDTO.getDateOfBirth());
	Department dept = new Department();
	dept.setDeptName(userDTO.getDepartment().getDeptName());
	dept.setId(userDTO.getDepartment().getId());
	Organization org = new Organization();
	org.setId(userDTO.getDepartment().getOrganization().getId());
	org.setHierarchyId(userDTO.getDepartment().getOrganization().getHierarchyId());
	org.setOrgName(userDTO.getDepartment().getOrganization().getOrgName());
	dept.setOrganization(org);
	userEntity.setDepartment(dept);
	Designation desg = new Designation();
	desg.setDesig(userDTO.getDesignation().getDesig());
	desg.setId(userDTO.getDesignation().getId());
	userEntity.setDesignation(desg);
	userEntity.setEmail(userDTO.getEmail());
	userEntity.setEndDate(userDTO.getEndDate());
	userEntity.setFirstName(userDTO.getFirstName());
	userEntity.setFromDate(userDTO.getFromDate());
	userEntity.setGender(userDTO.getGender());
	userEntity.setIsEnabled(userDTO.getIsEnabled());
	userEntity.setLastName(userDTO.getLastName());
	userEntity.setMobile(userDTO.getMobile());
	userEntity.setModifiedBy(userDTO.getModifiedBy());
	userEntity.setModifiedOn(userDTO.getModifiedOn());
	userEntity.setOrganization(org);
	userEntity.setPassword(userDTO.getPassword().toString());
	userEntity.setPermAddr(userDTO.getPermAddr());
	userEntity.setState(userDTO.getState());
	userEntity.setCity(userDTO.getCity());
	userEntity.setCountry(userDTO.getCountry());
	userEntity.setZip(userDTO.getZip());
	userEntity.setFatherName(userDTO.getFatherName());
	userEntity.setSpouseName(userDTO.getSpouseName());
	userEntity.setPassport(userDTO.getPassport());

	userEntity.setUserName(userDTO.getUserName());
	userEntity.setId(userDTO.getId());
	userEntity.setLocation(null==userDTO.getLocation()?null:prepareLocationEntity(userDTO.getLocation()));
	return userEntity;
    }

    
    /*
     * preparing LoxationMaster entity from LocationMasterDTO
     */
    private LocationMaster prepareLocationEntity(LocationMasterDTO location) {
	LocationMaster locationMaster=new LocationMaster();
	locationMaster.setCreatedBy(location.getCreatedBy());
	locationMaster.setCreatedOn(location.getCreatedOn());
	locationMaster.setId(location.getId());
	locationMaster.setLocationArea(location.getLocationArea());
	locationMaster.setLocationCity(location.getLocationCity());
	locationMaster.setLocationCountry(location.getLocationCountry());
	locationMaster.setLocationPin(location.getLocationPin());
	locationMaster.setLocationState(location.getLocationState());
	locationMaster.setModifiedBy(location.getModifiedBy());
	locationMaster.setModifiedOn(location.getModifiedOn());
	return locationMaster;
    }

    
    /*
     * (non-Javadoc)
     * @see com.easybusiness.usermanagement.services.approvermaster.ApproverMasterService#deleteApproveMaster(java.lang.Long)
     * deleting approver by taskid
     * DELETE method for APPROVER_MASTER table with param taskid
     */
    @Override
    @CrossOrigin(origins = USER_HOST_SERVER)
    @RequestMapping(value = "deleteApproveMaster/{taskid}", method = RequestMethod.DELETE)
    @ResponseBody
    public void deleteApproveMaster(@PathVariable("taskid") Long taskId) {

	approverMasterDao.deleteApproverMaster(taskId);
    }

    
    /*
     * preparing ApproverMasterDTO from ApproverMaster entity
     */
    private ApproverMasterDTO prepareApproverMasterDTO(ApproverMaster approverMaster) {
	ApproverMasterDTO approverMasterDTO = new ApproverMasterDTO();
	approverMasterDTO.setId(approverMaster.getId());
	approverMasterDTO.setModifiedBy(approverMaster.getModifiedBy());
	approverMasterDTO.setModifiedOn(approverMaster.getModifiedOn());
	approverMasterDTO.setTaskDesc(approverMaster.getTaskDesc());
	approverMasterDTO
		.setUser1(null == approverMaster.getUser1() ? null : prepareUserDTO(approverMaster.getUser1()));
	approverMasterDTO
		.setUser2(null == approverMaster.getUser2() ? null : prepareUserDTO(approverMaster.getUser2()));
	approverMasterDTO
		.setUser3(null == approverMaster.getUser3() ? null : prepareUserDTO(approverMaster.getUser3()));
	approverMasterDTO
		.setUser4(null == approverMaster.getUser4() ? null : prepareUserDTO(approverMaster.getUser4()));
	approverMasterDTO
		.setUser5(null == approverMaster.getUser5() ? null : prepareUserDTO(approverMaster.getUser5()));
	return approverMasterDTO;
    }

    
    /*
     * preparing UserDTO from User entity
     */
    private UserDTO prepareUserDTO(User userEntity) {
	UserDTO userDTO = new UserDTO();
	userDTO.setAlternateEmail(userEntity.getAlternateEmail());
	userDTO.setDateOfBirth(userEntity.getDateOfBirth());
	DepartmentDto deptDO = new DepartmentDto();
	deptDO.setDeptName(userEntity.getDepartment().getDeptName());
	deptDO.setId(userEntity.getDepartment().getId());
	OrganizationDto orgDTO = new OrganizationDto();
	orgDTO.setId(userEntity.getDepartment().getOrganization().getId());
	orgDTO.setHierarchyId(userEntity.getDepartment().getOrganization().getHierarchyId());
	orgDTO.setOrgName(userEntity.getDepartment().getOrganization().getOrgName());
	deptDO.setOrganization(orgDTO);;
	userDTO.setDepartment(deptDO);
	DesignationDto desigDTO = new DesignationDto();
	desigDTO.setDesig(userEntity.getDesignation().getDesig());
	desigDTO.setId(userEntity.getDesignation().getId());
	userDTO.setDesignation(desigDTO);
	userDTO.setEmail(userEntity.getEmail());
	userDTO.setEndDate(userEntity.getEndDate());
	userDTO.setFirstName(userEntity.getFirstName());
	userDTO.setFromDate(userEntity.getFromDate());
	userDTO.setGender(userEntity.getGender());
	userDTO.setId(userEntity.getId());
	userDTO.setIsEnabled(userEntity.getIsEnabled());
	userDTO.setLastName(userEntity.getLastName());
	userDTO.setMobile(userEntity.getMobile());
	userDTO.setModifiedBy(userEntity.getModifiedBy());
	userDTO.setModifiedOn(userEntity.getModifiedOn());
	userDTO.setOrganization(orgDTO);
	userDTO.setPassword(userEntity.getPassword());
	userDTO.setUserName(userEntity.getUserName());

	userDTO.setPermAddr(userEntity.getPermAddr());
	userDTO.setState(userEntity.getState());
	userDTO.setCity(userEntity.getCity());
	userDTO.setCountry(userEntity.getCountry());
	userDTO.setZip(userEntity.getZip());
	userDTO.setFatherName(userEntity.getFatherName());
	userDTO.setSpouseName(userEntity.getSpouseName());
	userDTO.setPassport(userEntity.getPassport());
	userDTO.setLocation(null==userEntity.getLocation()?null:prepareLocationDTO(userEntity.getLocation()));
	

	return userDTO;
    }

    
    /*
     * preparing LocationMasterDTO from LocationMaster entity
     */
    private LocationMasterDTO prepareLocationDTO(LocationMaster location) {
	LocationMasterDTO locationMaster=new LocationMasterDTO();
	locationMaster.setCreatedBy(location.getCreatedBy());
	locationMaster.setCreatedOn(location.getCreatedOn());
	locationMaster.setId(location.getId());
	locationMaster.setLocationArea(location.getLocationArea());
	locationMaster.setLocationCity(location.getLocationCity());
	locationMaster.setLocationCountry(location.getLocationCountry());
	locationMaster.setLocationPin(location.getLocationPin());
	locationMaster.setLocationState(location.getLocationState());
	locationMaster.setModifiedBy(location.getModifiedBy());
	locationMaster.setModifiedOn(location.getModifiedOn());
	return locationMaster;
    }

}
