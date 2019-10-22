package com.easybusiness.usermanagement.services.serviceimpl;

import static com.easybusiness.usermanagement.constant.UserManagementConstant.EMAIL_DOMAIN;
import static com.easybusiness.usermanagement.constant.UserManagementConstant.USER_HOST_SERVER;

import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.sql.Blob;
import java.sql.Date;
import java.sql.SQLException;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import java.util.concurrent.TimeUnit;

import javax.imageio.ImageIO;
import javax.sql.rowset.serial.SerialBlob;

import org.apache.catalina.Server;
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

import com.easybusiness.usermanagement.DTO.CityDTO;
import com.easybusiness.usermanagement.DTO.CountryDTO;
import com.easybusiness.usermanagement.DTO.DepartmentDto;
import com.easybusiness.usermanagement.DTO.DesignationDto;
import com.easybusiness.usermanagement.DTO.LocationMasterDTO;
import com.easybusiness.usermanagement.DTO.OrganizationDto;
import com.easybusiness.usermanagement.DTO.StateDTO;
import com.easybusiness.usermanagement.DTO.UserAcademicsDTO;
import com.easybusiness.usermanagement.DTO.UserDTO;
import com.easybusiness.usermanagement.DTO.UserProfessionDTO;
import com.easybusiness.usermanagement.dao.CityDao;
import com.easybusiness.usermanagement.dao.CountryDao;
import com.easybusiness.usermanagement.dao.LocationMasterDao;
import com.easybusiness.usermanagement.dao.StateDao;
import com.easybusiness.usermanagement.dao.UserAcademicsDao;
import com.easybusiness.usermanagement.dao.UserDao;
import com.easybusiness.usermanagement.dao.UserLoginDetailsDao;
import com.easybusiness.usermanagement.dao.UserProfessionDao;
import com.easybusiness.usermanagement.entity.City;
import com.easybusiness.usermanagement.entity.Country;
import com.easybusiness.usermanagement.entity.Department;
import com.easybusiness.usermanagement.entity.Designation;
import com.easybusiness.usermanagement.entity.LocationMaster;
import com.easybusiness.usermanagement.entity.Organization;
import com.easybusiness.usermanagement.entity.State;
import com.easybusiness.usermanagement.entity.User;
import com.easybusiness.usermanagement.entity.UserAcademics;
import com.easybusiness.usermanagement.entity.UserLoginDetails;
import com.easybusiness.usermanagement.entity.UserProfession;
import com.easybusiness.usermanagement.repository.UserRepository;
import com.easybusiness.usermanagement.services.UserService;
import com.google.common.hash.Hashing;


/*
 * Service and RestController class for User entity
 */
@RestController
@RequestMapping("/easybusiness/user/")
public class UserServiceImpl implements UserService {

    @Autowired
    UserDao userDao;
    
    @Autowired
    CountryDao countryDao;
    
    @Autowired
    StateDao stateDao;
    
    @Autowired
    CityDao cityDao;
    
    @Autowired
    UserRepository userRepo;

    @Autowired
    UserProfessionDao userProfessionDao;

    @Autowired
    UserAcademicsDao userAcademicsDao;
    
    @Autowired
    UserLoginDetailsDao loginDao;
    
    @Autowired
    LocationMasterDao locationDao;

    private static final Logger LOGGER = LoggerFactory.getLogger(UserServiceImpl.class);

    
    /*
     * (non-Javadoc)
     * @see com.easybusiness.usermanagement.services.user.UserService#getUser(java.lang.String)
     * fetching user by username
     * GET method with param "username"
     */
    @Override
    @CrossOrigin(origins = USER_HOST_SERVER)
    @RequestMapping(value = "getByUserName/{username}", method = RequestMethod.GET)
    @ResponseBody
    public ResponseEntity<UserDTO> getUser(@PathVariable("username") String userName) {
	System.out.println("in get user");
	User userEntity = userDao.findByUserName(userName).get();	//fetching user entity by username
	return new ResponseEntity<UserDTO>(prepareUserDTO(userEntity), HttpStatus.OK);
    }

    //preparing user DTO for fetching user details
    private UserDTO prepareUserDTO(User userEntity) {
	UserDTO userDTO = new UserDTO();	//creating blank user DTO object
	
	userDTO.setEpfNo(userEntity.getEpfNo());
	userDTO.setEsiNo(userEntity.getEsiNo());
	
	if(userEntity.getCountry() != null) {
		CountryDTO countryEmp = new CountryDTO();
		Country country = countryDao.getCountryById(Long.valueOf(userEntity.getCountry()));
		
		countryEmp.setCountryName(country.getcountryName());
		countryEmp.setId(country.getId());
		
		userDTO.setCountryName(countryEmp);
	}
	
	if(userEntity.getState() != null) {
		StateDTO stateEmp = new StateDTO();
		State state = stateDao.getStateById(Long.valueOf(userEntity.getState()));
		
		stateEmp.setStateName(state.getstateName());
		stateEmp.setId(state.getId());
		
		userDTO.setStateName(stateEmp);
	}
	
	if(userEntity.getCity() != null) {
		City city = cityDao.getCityById(Long.valueOf(userEntity.getCity()));
		CityDTO cityEmp = new CityDTO();
		
		cityEmp.setCityName(city.getcityName());
		cityEmp.setId(city.getId());
		
		userDTO.setCityName(cityEmp);
	}
	
	userDTO.setAlternateEmail(userEntity.getAlternateEmail());
	userDTO.setDateOfBirth(userEntity.getDateOfBirth());
	
	//getting department object
	DepartmentDto deptDO = new DepartmentDto();
	try {
	    deptDO.setDeptName(userEntity.getDepartment().getDeptName());
	    deptDO.setId(userEntity.getDepartment().getId());

	    //getting organization object
	    OrganizationDto orgDTO = new OrganizationDto();

	    orgDTO.setId(userEntity.getDepartment().getOrganization().getId());
	    orgDTO.setHierarchyId(userEntity.getDepartment().getOrganization().getHierarchyId());
	    orgDTO.setOrgName(userEntity.getDepartment().getOrganization().getOrgName());
	    orgDTO.setLocationId(userEntity.getDepartment().getOrganization().getLocationId());
	    orgDTO.setModBy(userEntity.getDepartment().getOrganization().getModBy());
	    orgDTO.setModOn(userEntity.getDepartment().getOrganization().getModOn());
	    orgDTO.setOrgType(userEntity.getDepartment().getOrganization().getOrgType());
	    orgDTO.setShortCode(userEntity.getDepartment().getOrganization().getShortCode());
	    
	    deptDO.setOrganization(orgDTO);
	    
	    userDTO.setDepartment(deptDO); //setting department DTO
	    userDTO.setOrganization(orgDTO); //setting organization DTO
	} catch (Exception e) {
	    LOGGER.error("error in getting organization/department of user {} {}", userEntity.getUserName(),
		    e.getMessage());
	}
	
	//getting designation DTO
	try {
	    DesignationDto desigDTO = new DesignationDto();

	    desigDTO.setDesig(userEntity.getDesignation().getDesig());
	    desigDTO.setId(userEntity.getDesignation().getId());
	    desigDTO.setModBy(userEntity.getDesignation().getModBy());
	    desigDTO.setModOn(userEntity.getDesignation().getModOn());

	    userDTO.setDesignation(desigDTO);
	} catch (Exception e) {
	    LOGGER.error("error in getting designation of user {} {}", userEntity.getUserName(), e.getMessage());
	}
	
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
	userDTO.setTypeOfEmployment(userEntity.getTypeOfEmployment());
	
	//getting user image
	int usrImgLength;
	try {
		if(userEntity.getUserImg() != null) {
		usrImgLength = (int) userEntity.getUserImg().length();
		System.out.println(usrImgLength);
		if(0 != usrImgLength) {
			userDTO.setUserImg(userEntity.getUserImg().getBytes(1, usrImgLength));
		}else {
			userDTO.setUserImg(null);
		}
		}
	} catch (SQLException e) {
		e.printStackTrace();
	}

	userDTO.setUserName(userEntity.getUserName());
	userDTO.setPermAddr(userEntity.getPermAddr());
	userDTO.setState(userEntity.getState());
	userDTO.setCity(userEntity.getCity());
	userDTO.setCountry(userEntity.getCountry());
	userDTO.setZip(userEntity.getZip());
	userDTO.setFatherName(userEntity.getFatherName());
	userDTO.setSpouseName(userEntity.getSpouseName());
	userDTO.setPassport(userEntity.getPassport());
	userDTO.setLocation(null == userEntity.getLocation() ? null : prepareLocationDTO(userEntity.getLocation()));
	

	return userDTO;
	
    }

    //preparing location master DTO for fetching location
    private LocationMasterDTO prepareLocationDTO(LocationMaster location) {
	LocationMasterDTO locationMaster = new LocationMasterDTO();
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
     * @see com.easybusiness.usermanagement.services.user.UserService#persistUser(com.easybusiness.usermanagement.DTO.UserDTO)
     * saving user entity to DB
     * POST method with request body "UserDTO"
     */
    @Override
    @CrossOrigin(origins = USER_HOST_SERVER)
    @RequestMapping(value = "addUser", method = RequestMethod.POST)
    @ResponseBody
    public ResponseEntity<UserDTO> persistUser(@RequestBody UserDTO userDTO) {

	System.out.println(
		"user dto in persistence layer to be set is " + userDTO.toString() + "`" + userDTO.getUserImg());

	User userEntity = new User();	//creating blank user object
	
	userEntity.setAlternateEmail(userDTO.getAlternateEmail());
	userEntity.setDateOfBirth(userDTO.getDateOfBirth());
	
	Department dept = new Department();		//creating blank department object
	
	dept.setDeptName(userDTO.getDepartment().getDeptName());
	dept.setId(userDTO.getDepartment().getId());
		
		//setting organization
		Organization org = new Organization();	//creating blank organization object
		
		org.setId(userDTO.getDepartment().getOrganization().getId());
		org.setHierarchyId(userDTO.getDepartment().getOrganization().getHierarchyId());
		org.setOrgName(userDTO.getDepartment().getOrganization().getOrgName());
		org.setLocationId(userDTO.getDepartment().getOrganization().getLocationId());
		
	dept.setOrganization(org);
	
	userEntity.setDepartment(dept);
	
	Designation desg = new Designation();	//creating blank designation object
	
	desg.setDesig(userDTO.getDesignation().getDesig());
	desg.setId(userDTO.getDesignation().getId());
	userEntity.setDesignation(desg);
	
	// userEntity.setEmail(userDTO.getEmail());
	userEntity.setEndDate(userDTO.getEndDate());
	userEntity.setFirstName(userDTO.getFirstName());
	userEntity.setFromDate(userDTO.getFromDate());
	userEntity.setGender(userDTO.getGender());
	userEntity.setIsEnabled(userDTO.getIsEnabled());
	userEntity.setLastName(userDTO.getLastName());
	userEntity.setMobile(userDTO.getMobile());
	userEntity.setModifiedBy(userDTO.getModifiedBy());
	userEntity.setModifiedOn(Date.valueOf(LocalDate.now()));
	userEntity.setOrganization(org);
	//userEntity.setPassword(userDTO.getPassword());
	
	//password hashing with sha256
	/*String sha256hex = Hashing.sha256()
							.hashString(userDTO.getPassword(), StandardCharsets.UTF_8)
							.toString();
	userEntity.setPassword(sha256hex);*/
	userEntity.setPassword(userDTO.getPassword());
	//System.out.println(sha256hex);
	
	userEntity.setTypeOfEmployment(userDTO.getTypeOfEmployment());
	// userEntity.setUserName(userDTO.getUserName());

	//unique username creation
	String uniqueUserName = prepareUniqueUserName((userDTO.getFirstName().toLowerCase()).charAt(0),
		userDTO.getLastName().toLowerCase());
	userEntity.setUserName(uniqueUserName);
	userEntity.setEmail(uniqueUserName + EMAIL_DOMAIN);

	userEntity.setPermAddr(userDTO.getPermAddr());
	userEntity.setState(userDTO.getState());
	userEntity.setCity(userDTO.getCity());
	userEntity.setCountry(userDTO.getCountry());
	userEntity.setZip(userDTO.getZip());
	userEntity.setFatherName(userDTO.getFatherName());
	userEntity.setSpouseName(userDTO.getSpouseName());
	userEntity.setPassport(userDTO.getPassport());
	LocationMaster location = locationDao.getLocationById(org.getLocationId());
	userEntity.setLocation(null == location ? null : prepareLocationEntity1(location));
	
	
	//saving image to db
	BufferedImage bufferedImage = null;
	try {
		InputStream inputStream = new ByteArrayInputStream(userDTO.getUserImg());
		bufferedImage = ImageIO.read(inputStream);
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		ImageIO.write(bufferedImage, "jpg", baos);
		Blob image = new SerialBlob(baos.toByteArray());
		userEntity.setUserImg(image);
	}catch(Exception e) {
		e.printStackTrace();
	}
	
	
	userDao.addUser(userEntity);
	
	User userProcEntity = userDao.findByUserName(uniqueUserName).get(); //getting the user object which just saved to the DB

	//calling stored procedure 
	userDao.storedProc(userProcEntity.getId(), userProcEntity.getDepartment().getOrganization().getLocationId());
	userDTO.setUserName(userEntity.getUserName());
	userDTO.setEmail(userEntity.getEmail());
	return new ResponseEntity<UserDTO>(userDTO, HttpStatus.CREATED);

    }

    /*
     * peparing unique username using first character of firstname and last name in lower case
     */
    private String prepareUniqueUserName(char firstCharOfFirstName, String lastName) {
	int countOfAlreadyPresentSimilarUserName = userDao.findCountOfUserName(firstCharOfFirstName + lastName);
	return countOfAlreadyPresentSimilarUserName == 0 ? (firstCharOfFirstName + lastName)
		: (firstCharOfFirstName + lastName + (countOfAlreadyPresentSimilarUserName + 1));
    }

    
    //preparing location master DTO
    private LocationMaster prepareLocationEntity(LocationMasterDTO location) {
	LocationMaster locationMaster = new LocationMaster();
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
    
    private LocationMaster prepareLocationEntity1(LocationMaster location) {
    	LocationMaster locationMaster = new LocationMaster();
    	locationMaster.setCreatedBy(location.getCreatedBy());
    	locationMaster.setCreatedOn(location.getCreatedOn());
    	locationMaster.setId(location.getId());
    	locationMaster.setLocationArea(location.getLocationArea());
    	locationMaster.setLocationCity(location.getLocationCity());
    	locationMaster.setLocationCountry(location.getLocationCountry());
    	locationMaster.setLocationPin(location.getLocationPin());
    	locationMaster.setLocationState(location.getLocationState());
    	locationMaster.setModifiedBy(location.getModifiedBy());
    	locationMaster.setModifiedOn(Date.valueOf(LocalDate.now()));
    	return locationMaster;
        }

    
    /*
     * (non-Javadoc)
     * @see com.easybusiness.usermanagement.services.user.UserService#updateUser(com.easybusiness.usermanagement.DTO.UserDTO)
     * updating user entity
     * POST method with request body of "UserDTO"
     */
    @SuppressWarnings("unused")
	@Override
    @CrossOrigin(origins = USER_HOST_SERVER)
    @RequestMapping(value = "updateUser", method = RequestMethod.POST)
    @ResponseBody
    public ResponseEntity<UserDTO> updateUser(@RequestBody UserDTO userDTO) {

	System.out.println(
		"user dto in persistence layer to be updated is " + userDTO.toString() + "`" + userDTO.getUserImg());
//	User userGetEntity = userDao.findByUserName(userDTO.getUserName()).get();
	if(userDTO.getId()!= 0) {
		
	User userEntity = userDao.findUserById(userDTO.getId());
//	User userEntity = new User();
	userEntity.setAlternateEmail(userDTO.getAlternateEmail());
	userEntity.setDateOfBirth(userDTO.getDateOfBirth());
	
	userEntity.setEsiNo(userDTO.getEsiNo());
	userEntity.setEpfNo(userDTO.getEpfNo());
	
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
	userEntity.setModifiedOn(Date.valueOf(LocalDate.now()));
	userEntity.setOrganization(org);

	//password encryption
		/*String sha256hex = Hashing.sha256()
								.hashString(userDTO.getPassword(), StandardCharsets.UTF_8).toString();*/
//		userDTO.setPassword(sha256hex);
		userDTO.setPassword(userEntity.getPassword());
		
	
	
	userEntity.setTypeOfEmployment(userDTO.getTypeOfEmployment());
	//userEntity.setUserName(userDTO.getUserName());
	
	//saving image to db
		BufferedImage bufferedImage = null;
		if(userDTO.getUserImg() != null) {
			try {
				InputStream inputStream = new ByteArrayInputStream(userDTO.getUserImg());
				bufferedImage = ImageIO.read(inputStream);
				ByteArrayOutputStream baos = new ByteArrayOutputStream();
				ImageIO.write(bufferedImage, "jpg", baos);
				Blob image = new SerialBlob(baos.toByteArray());
				userEntity.setUserImg(image);
			}catch(Exception e) {
				e.printStackTrace();
			}
		}else {
			userEntity.setUserImg(null);
		}
		

	userEntity.setPermAddr(userDTO.getPermAddr());
	userEntity.setState(userDTO.getState());
	userEntity.setCity(userDTO.getCity());
	userEntity.setCountry(userDTO.getCountry());
	userEntity.setZip(userDTO.getZip());
	userEntity.setFatherName(userDTO.getFatherName());
	userEntity.setSpouseName(userDTO.getSpouseName());
	userEntity.setPassport(userDTO.getPassport());
	userEntity.setId(userEntity.getId());

	LocationMaster location = locationDao.getLocationById(org.getLocationId());
	userEntity.setLocation(null == location ? null : prepareLocationEntity1(location));
	

	System.out.println("user Entity to send to dao is " + userEntity);
	
	//userDao.saveEntity(userEntity);
//	userDao.save(userEntity);
	userDao.addUser(userEntity);
	System.out.println("inside if "+userDTO.getId());
//	System.out.println(image);
	System.out.println(userDTO.getUserImg());
	}else {
		User userEntity = new User();	//creating blank user object
		
		userEntity.setAlternateEmail(userDTO.getAlternateEmail());
		userEntity.setDateOfBirth(userDTO.getDateOfBirth());
		
		Department dept = new Department();		//creating blank department object
		
		dept.setDeptName(userDTO.getDepartment().getDeptName());
		dept.setId(userDTO.getDepartment().getId());
			
			//setting organization
			Organization org = new Organization();	//creating blank organization object
			
			org.setId(userDTO.getDepartment().getOrganization().getId());
			org.setHierarchyId(userDTO.getDepartment().getOrganization().getHierarchyId());
			org.setOrgName(userDTO.getDepartment().getOrganization().getOrgName());
			org.setLocationId(userDTO.getDepartment().getOrganization().getLocationId());
			
		dept.setOrganization(org);
		
		userEntity.setDepartment(dept);
		
		Designation desg = new Designation();	//creating blank designation object
		
		desg.setDesig(userDTO.getDesignation().getDesig());
		desg.setId(userDTO.getDesignation().getId());
		userEntity.setDesignation(desg);
		
		// userEntity.setEmail(userDTO.getEmail());
		userEntity.setEndDate(userDTO.getEndDate());
		userEntity.setFirstName(userDTO.getFirstName());
		userEntity.setFromDate(userDTO.getFromDate());
		userEntity.setGender(userDTO.getGender());
		userEntity.setIsEnabled(userDTO.getIsEnabled());
		userEntity.setLastName(userDTO.getLastName());
		userEntity.setMobile(userDTO.getMobile());
		userEntity.setModifiedBy(userDTO.getModifiedBy());
		userEntity.setModifiedOn(Date.valueOf(LocalDate.now()));
		userEntity.setOrganization(org);
		//userEntity.setPassword(userDTO.getPassword());
		
		//password hashing with sha256
		/*String sha256hex = Hashing.sha256()
								.hashString(userDTO.getPassword(), StandardCharsets.UTF_8)
								.toString();
		userEntity.setPassword(sha256hex);*/
		userEntity.setPassword(userDTO.getPassword());
		//System.out.println(sha256hex);
		
		userEntity.setTypeOfEmployment(userDTO.getTypeOfEmployment());
		// userEntity.setUserName(userDTO.getUserName());

		//unique username creation
		String uniqueUserName = prepareUniqueUserName((userDTO.getFirstName().toLowerCase()).charAt(0),
			userDTO.getLastName().toLowerCase());
		userEntity.setUserName(uniqueUserName);
		userEntity.setEmail(uniqueUserName + EMAIL_DOMAIN);

		userEntity.setPermAddr(userDTO.getPermAddr());
		userEntity.setState(userDTO.getState());
		userEntity.setCity(userDTO.getCity());
		userEntity.setCountry(userDTO.getCountry());
		userEntity.setZip(userDTO.getZip());
		userEntity.setFatherName(userDTO.getFatherName());
		userEntity.setSpouseName(userDTO.getSpouseName());
		userEntity.setPassport(userDTO.getPassport());
		LocationMaster location = locationDao.getLocationById(org.getLocationId());
		userEntity.setLocation(null == location ? null : prepareLocationEntity1(location));
		
		
		//saving image to db
		BufferedImage bufferedImage = null;
		Blob image = null;
		try {
			InputStream inputStream = new ByteArrayInputStream(userDTO.getUserImg());
			bufferedImage = ImageIO.read(inputStream);
			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			ImageIO.write(bufferedImage, "jpg", baos);
			image = new SerialBlob(baos.toByteArray());
			
		}catch(Exception e) {
			e.printStackTrace();
		}
		System.out.println(image);
		userEntity.setUserImg(image);
		
		userDao.addUser(userEntity);
		System.out.println("inside if "+userDTO.getId());
		User userProcEntity = userDao.findByUserName(uniqueUserName).get(); //getting the user object which just saved to the DB

		//calling stored procedure 
		userDao.storedProc(userProcEntity.getId(), userProcEntity.getDepartment().getOrganization().getLocationId());
	}
	
	return new ResponseEntity<UserDTO>(userDTO, HttpStatus.CREATED);

    }

    
    /*
     * (non-Javadoc)
     * @see com.easybusiness.usermanagement.services.user.UserService#populateUserList()
     * fetching all users
     * GET method for user_details table
     */
    @Override
    @CrossOrigin(origins = USER_HOST_SERVER)
    @RequestMapping(value = "getAllUsers", method = RequestMethod.GET)
    @ResponseBody
    public List<UserDTO> populateUserList() {
	List<UserDTO> userDTOList = new ArrayList<UserDTO>();
	try {
	    List<User> userEntityList = userDao.findAll();
//		List<User> userEntityList = userDao.findAllOrdered();

	    userEntityList.forEach(userEntity -> {
		if (userEntity.getIsEnabled() == 1) {
		    userDTOList.add(prepareUserDTO(userEntity));
		}
	    });

	} catch (Exception e) {
	    e.printStackTrace();
	}
	return userDTOList;
    }

    
    /*
     * (non-Javadoc)
     * @see com.easybusiness.usermanagement.services.user.UserService#populateOneUserDetails(java.lang.Long)
     * fetching user by user id
     * GET method for table user_detials with param userId
     */
    @Override
    @CrossOrigin(origins = USER_HOST_SERVER)
    @RequestMapping(value = "getByUserId/{userId}", method = RequestMethod.GET)
    @ResponseBody
    public UserDTO populateOneUserDetails(@PathVariable("userId") Long userId) {
	User userEntity = userDao.findUserById(userId);
	return prepareUserDTO(userEntity);
    }

    
    /*
     * (non-Javadoc)
     * @see com.easybusiness.usermanagement.services.user.UserService#destroyUser(java.lang.Long)
     * deleting user
     * DELETE method for user_details table with param userId
     */
    @Override
    @CrossOrigin(origins = USER_HOST_SERVER)
    @RequestMapping(value = "deleteUser/{userId}", method = RequestMethod.DELETE)
    @ResponseBody
    public void destroyUser(@PathVariable("userId") Long userId) {

	userDao.deleteUser(userId);
    }

    @Override
    public List<UserDTO> getFieldEq(Class<UserDTO> type, String propertyName, Object value, int offset, int size) {
	return null;
    }

    @Override
    public void persistUser(UserDTO loggedUser, boolean changePassword) {

    }

    
    /*
     * (non-Javadoc)
     * @see com.easybusiness.usermanagement.services.user.UserService#activateUser(java.lang.Long)
     * activating user 
     * POST method for user_details table with param userId
     * this method updates isEnabled field of user_details table to value 1
     */
    @Override
    @CrossOrigin(origins = USER_HOST_SERVER)
    @RequestMapping(value = "activateUser/{userId}", method = RequestMethod.POST)
    @ResponseBody
    public void activateUser(@PathVariable("userId") Long userId) {

    	User user = userDao.findUserById(userId);
    	user.setIsEnabled((long) 1);
    	
    	userDao.updateUser(user);
    	
    }

    
    /*
     * (non-Javadoc)
     * @see com.easybusiness.usermanagement.services.user.UserService#deActivateUser(java.lang.Long)
     * deactivating user
     *  POST method for user_details table with param userId
     *  this method updates isEnabled field of user_details table to value 0
     */
    @Override
    @CrossOrigin(origins = USER_HOST_SERVER)
    @RequestMapping(value = "deactivateUser/{userId}", method = RequestMethod.POST)
    @ResponseBody
    public void deActivateUser(@PathVariable("userId") Long userId) {

    	User user = userDao.findUserById(userId);
    	user.setIsEnabled((long) 0);
    	
    	userDao.updateUser(user);
    	
    }

    @Override
    public UserDTO getActiveUser(String email) {
	return null;
    }

    
    /*
     * (non-Javadoc)
     * @see com.easybusiness.usermanagement.services.user.UserService#getUserProfession(java.lang.Long)
     * fetching user profession from user_profession table
     * GET method with param userId
     */
    @Override
    @CrossOrigin(origins = USER_HOST_SERVER)
    @RequestMapping(value = "getUserProfession/{userid}", method = RequestMethod.GET)
    @ResponseBody
    public List<UserProfessionDTO> getUserProfession(@PathVariable("userid") Long userId) {
	System.out.println("in get user Profession");
	List<UserProfession> userProfessionEntity = userProfessionDao.getUserProfessionByUser(userId);
	List<UserProfessionDTO> userProfessionDTO = new ArrayList<>();
	if (null != userProfessionEntity) {

	    userProfessionEntity.forEach(userProfession->{
	    	userProfessionDTO.add(prepareUserProfessionDTO(userProfession));
	    	System.out.println("profession "+userProfession);
	    });

	}
	return userProfessionDTO;

    }

    
    /*
     * preparing user profession DTO for fetching user profession data
     */
    private UserProfessionDTO prepareUserProfessionDTO(UserProfession userProfession) {
    	
    	UserProfessionDTO userProfessionDTO = new UserProfessionDTO();
    	
    	long startDate =  userProfession.getProjectStartDate().getTime();
    	long endDate =  userProfession.getProjectEndDate().getTime();
    	String diff = "";
    	long timeDiff = (endDate-startDate);
    	diff = String.format("%d months", TimeUnit.MILLISECONDS.toDays(timeDiff)/30);
    	userProfessionDTO.setTotalExp(diff);
    	
    	userProfessionDTO.setId(userProfession.getId());
    	userProfessionDTO.setModBy(userProfession.getModBy());
    	userProfessionDTO.setModOn(userProfession.getModOn());
    	userProfessionDTO.setOrganization(userProfession.getOrganisation());
    	userProfessionDTO.setOtherSkill(userProfession.getOtherSkill());
    	userProfessionDTO.setPrimarySkill(userProfession.getPrimarySkill());
    	userProfessionDTO.setProjectDesc(userProfession.getProjectDesc());
    	userProfessionDTO.setProjectDuration(userProfession.getProjectDuration());
    	userProfessionDTO.setProjectEndDate(userProfession.getProjectEndDate());
    	userProfessionDTO.setProjectName(userProfession.getProjectName());
    	userProfessionDTO.setProjectRole(userProfession.getProjectRole());
    	userProfessionDTO.setProjectStartDate(userProfession.getProjectStartDate());
    	userProfessionDTO.setUser(userProfession.getUser());
	    
	    
		return userProfessionDTO;
	}

    
    /*
     * (non-Javadoc)
     * @see com.easybusiness.usermanagement.services.user.UserService#persistUserProfession(com.easybusiness.usermanagement.DTO.UserProfessionDTO)
     * saving user profession to DB
     * POST method for user_profession table with request body "UserProfessionDTO"
     */
	@Override
    @CrossOrigin(origins = USER_HOST_SERVER)
    @RequestMapping(value = "addUserProfession", method = RequestMethod.POST)
    @ResponseBody
    public ResponseEntity<UserProfessionDTO> persistUserProfession(@RequestBody UserProfessionDTO userProfession) {
	

	UserProfession userProfessionValue = new UserProfession();
	System.out.println("user profession DTO to be sent to Dao is " + userProfession.toString());
	
	userProfessionValue.setModBy(userProfession.getModBy());
	userProfessionValue.setModOn(Date.valueOf(LocalDate.now()));
	userProfessionValue.setOrganization(userProfession.getOrganization());
	userProfessionValue.setOtherSkill(userProfession.getOtherSkill());
	userProfessionValue.setPrimarySkill(userProfession.getPrimarySkill());
	userProfessionValue.setProjectDesc(userProfession.getProjectDesc());
	userProfessionValue.setProjectDuration(userProfession.getProjectDuration());
	userProfessionValue.setProjectEndDate(userProfession.getProjectEndDate());
	userProfessionValue.setProjectName(userProfession.getProjectName());
	userProfessionValue.setProjectRole(userProfession.getProjectRole());
	userProfessionValue.setProjectStartDate(userProfession.getProjectStartDate());
	userProfessionValue.setUser(userProfession.getUser());

	userProfessionDao.addUserProfession(userProfessionValue);
	return new ResponseEntity<UserProfessionDTO>(userProfession, HttpStatus.CREATED);
    }

	
	/*
	 * (non-Javadoc)
	 * @see com.easybusiness.usermanagement.services.user.UserService#updateUserProfession(com.easybusiness.usermanagement.DTO.UserProfessionDTO)
	 * updating user profession
	 * POST method for user_profession table with request body UserProfessionDTO
	 * this method updates the user profession finding by profession id
	 */
    @Override
    @CrossOrigin(origins = USER_HOST_SERVER)
    @RequestMapping(value = "updateUserProfession", method = RequestMethod.POST)
    @ResponseBody
    public ResponseEntity<UserProfessionDTO> updateUserProfession(
    		@RequestBody UserProfessionDTO userProfession) {
	

    	if(userProfession.getId()!=null) {
				UserProfession userProfessionValue = userProfessionDao.getProfessionById(userProfession.getId());
				System.out.println("user profession DTO to be sent to Dao is " + userProfession.toString());
				
				userProfessionValue.setModBy(userProfession.getModBy());
				userProfessionValue.setModOn(Date.valueOf(LocalDate.now()));
				userProfessionValue.setOrganization(userProfession.getOrganization());
				userProfessionValue.setOtherSkill(userProfession.getOtherSkill());
				userProfessionValue.setPrimarySkill(userProfession.getPrimarySkill());
				userProfessionValue.setProjectDesc(userProfession.getProjectDesc());
				userProfessionValue.setProjectDuration(userProfession.getProjectDuration());
				userProfessionValue.setProjectEndDate(userProfession.getProjectEndDate());
				userProfessionValue.setProjectName(userProfession.getProjectName());
				userProfessionValue.setProjectRole(userProfession.getProjectRole());
				userProfessionValue.setProjectStartDate(userProfession.getProjectStartDate());
			
				userProfessionDao.updateUserProfession(userProfessionValue);
    	}else {
    		UserProfession userProfessionValue = new UserProfession();
    		System.out.println("user profession DTO to be sent to Dao is " + userProfession.toString());
    		
    		userProfessionValue.setModBy(userProfession.getModBy());
    		userProfessionValue.setModOn(userProfession.getModOn());
    		userProfessionValue.setOrganization(userProfession.getOrganization());
    		userProfessionValue.setOtherSkill(userProfession.getOtherSkill());
    		userProfessionValue.setPrimarySkill(userProfession.getPrimarySkill());
    		userProfessionValue.setProjectDesc(userProfession.getProjectDesc());
    		userProfessionValue.setProjectDuration(userProfession.getProjectDuration());
    		userProfessionValue.setProjectEndDate(userProfession.getProjectEndDate());
    		userProfessionValue.setProjectName(userProfession.getProjectName());
    		userProfessionValue.setProjectRole(userProfession.getProjectRole());
    		userProfessionValue.setProjectStartDate(userProfession.getProjectStartDate());
    		userProfessionValue.setUser(userProfession.getUser());

    		userProfessionDao.addUserProfession(userProfessionValue);
    	}
	
	return new ResponseEntity<UserProfessionDTO>(userProfession, HttpStatus.CREATED);
    }

    /*private User prepareUserProfessionEntity(UserProfessionDTO userProfessionDTO) {
	User userEntity = new User();
	userEntity.setAlternateEmail(userProfessionDTO.getUser().getAlternateEmail());
	userEntity.setDateOfBirth(userProfessionDTO.getUser().getDateOfBirth());
	Department dept = new Department();
	dept.setDeptName(userProfessionDTO.getUser().getDepartment().getDeptName());
	dept.setId(userProfessionDTO.getUser().getDepartment().getId());
	Organization org = new Organization();
	org.setId(userProfessionDTO.getUser().getDepartment().getOrganization().getId());
	org.setOrgLocation(userProfessionDTO.getUser().getDepartment().getOrganization().getOrgLocation());
	org.setOrgName(userProfessionDTO.getUser().getDepartment().getOrganization().getOrgName());
	dept.setOrganization(org);
	userEntity.setDepartment(dept);
	Designation desg = new Designation();
	desg.setDesig(userProfessionDTO.getUser().getDesignation().getDesig());
	desg.setId(userProfessionDTO.getUser().getDesignation().getId());
	userEntity.setDesignation(desg);
	userEntity.setEmail(userProfessionDTO.getUser().getEmail());
	userEntity.setEndDate(userProfessionDTO.getUser().getEndDate());
	userEntity.setFirstName(userProfessionDTO.getUser().getFirstName());
	userEntity.setFromDate(userProfessionDTO.getUser().getFromDate());
	userEntity.setGender(userProfessionDTO.getUser().getGender());
	userEntity.setIsEnabled(userProfessionDTO.getUser().getIsEnabled());
	userEntity.setLastName(userProfessionDTO.getUser().getLastName());
	userEntity.setMobile(userProfessionDTO.getUser().getMobile());
	userEntity.setModifiedBy(userProfessionDTO.getUser().getModifiedBy());
	userEntity.setModifiedOn(userProfessionDTO.getUser().getModifiedOn());
	userEntity.setOrganization(org);
	userEntity.setPassword(userProfessionDTO.getUser().getPassword().toString());
	userEntity.setTypeOfEmployment(userProfessionDTO.getUser().getTypeOfEmployment());
	userEntity.setUserName(userProfessionDTO.getUser().getUserName());
	userEntity.setId(userProfessionDTO.getUser().getId());

	userEntity.setPermAddr(userProfessionDTO.getUser().getPermAddr());
	userEntity.setState(userProfessionDTO.getUser().getState());
	userEntity.setCity(userProfessionDTO.getUser().getCity());
	userEntity.setCountry(userProfessionDTO.getUser().getCountry());
	userEntity.setZip(userProfessionDTO.getUser().getZip());
	userEntity.setFatherName(userProfessionDTO.getUser().getFatherName());
	userEntity.setSpouseName(userProfessionDTO.getUser().getSpouseName());
	userEntity.setPassport(userProfessionDTO.getUser().getPassport());
	userEntity.setLocation(null == userProfessionDTO.getUser().getLocation() ? null
		: prepareLocationEntity(userProfessionDTO.getUser().getLocation()));
	userEntity.setUnitId(userProfessionDTO.getUser().getUnitId());

	return userEntity;
    }*/

    
    /*
     * (non-Javadoc)
     * @see com.easybusiness.usermanagement.services.user.UserService#getUserAcademics(java.lang.Long)
     * fetching user academics ie user education by user id
     * GET method for user_education table with param userid
     */
    @Override
    @CrossOrigin(origins = USER_HOST_SERVER)
    @RequestMapping(value = "getUserAcademics/{userid}", method = RequestMethod.GET)
    @ResponseBody
    public List<UserAcademicsDTO> getUserAcademics(@PathVariable("userid") Long userId) {
	System.out.println("in get user Academics");
	List<UserAcademics> userAcademicsEntity = userAcademicsDao
		.getUserAcademics(userId);
	List<UserAcademicsDTO> userAcademicsDTO = new ArrayList<>();
	if (null != userAcademicsEntity) {

	    userAcademicsEntity.forEach(userAcademics->{
	    	userAcademicsDTO.add(prepareUserAcademicsDTO(userAcademics));
	    });

	}
	return userAcademicsDTO;

    }

    
    /*
     * creating user academics DTO for fetching user profession data
     */
    private UserAcademicsDTO prepareUserAcademicsDTO(UserAcademics userAcademics) {
    	UserAcademicsDTO userAcademicsDTO = new UserAcademicsDTO();
    	
    	userAcademicsDTO.setId(userAcademics.getId());
	    userAcademicsDTO.setUser(userAcademics.getUser());
	    userAcademicsDTO.setHighestDegree(userAcademics.getHighestDegree());
	    userAcademicsDTO.setIsValid(userAcademics.getIsValid());
	    userAcademicsDTO.setModBy(userAcademics.getModBy());
	    userAcademicsDTO.setModOn(userAcademics.getModOn());
	    userAcademicsDTO.setPassingYear(userAcademics.getPassingYear());
	    userAcademicsDTO.setUniversity(userAcademics.getUniversity());
	    userAcademicsDTO.setUser(userAcademics.getUser());
	    userAcademicsDTO.setValidity(userAcademics.getValidity());
		
	    return userAcademicsDTO;
	}

    
    /*
     * (non-Javadoc)
     * @see com.easybusiness.usermanagement.services.user.UserService#persistUserAcademics(com.easybusiness.usermanagement.DTO.UserAcademicsDTO)
     * saving user academics data to table user_education table
     * POST method for table user_education with request body UserAcademicsDTO
     */
	@Override
    @CrossOrigin(origins = USER_HOST_SERVER)
    @RequestMapping(value = "addUserAcademics", method = RequestMethod.POST)
    @ResponseBody
    public ResponseEntity<UserAcademicsDTO> persistUserAcademics(@RequestBody UserAcademicsDTO userAcademics) {

	UserAcademics userAcademicsValue = new UserAcademics();
	System.out.println("user Academics DTO to be sent to Dao is " + userAcademics.toString());
	
	userAcademicsValue.setIsValid(userAcademics.getIsValid());
	userAcademicsValue.setHighestDegree(userAcademics.getHighestDegree());
	userAcademicsValue.setModBy(userAcademics.getModBy());
	userAcademicsValue.setModOn(Date.valueOf(LocalDate.now()));
	userAcademicsValue.setPassingYear(userAcademics.getPassingYear());
	userAcademicsValue.setUniversity(userAcademics.getUniversity());
	userAcademicsValue.setUser(userAcademics.getUser());
	userAcademicsValue.setValidity(userAcademics.getValidity());

	userAcademicsDao.addUserAcademics(userAcademicsValue);
	return new ResponseEntity<UserAcademicsDTO>(userAcademics, HttpStatus.CREATED);
    }

	
	/*
	 * (non-Javadoc)
	 * @see com.easybusiness.usermanagement.services.user.UserService#updateUserAcademics(com.easybusiness.usermanagement.DTO.UserAcademicsDTO)
	 * updating user education
	 * POST method for table user_education with request body UserAacademicsDTO
	 */
    @Override
    @CrossOrigin(origins = USER_HOST_SERVER)
    @RequestMapping(value = "updateUserAcademics", method = RequestMethod.POST)
    @ResponseBody
    public ResponseEntity<UserAcademicsDTO> updateUserAcademics(
    				@RequestBody UserAcademicsDTO userAcademics) {

    	if(userAcademics.getId() != null) {
				UserAcademics userAcademicsValue = userAcademicsDao.getAcademicsById(userAcademics.getId());
				System.out.println("user Academics DTO to be sent to Dao is " + userAcademics.toString());
				userAcademicsValue.setIsValid(userAcademics.getIsValid());
				userAcademicsValue.setHighestDegree(userAcademics.getHighestDegree());
				userAcademicsValue.setModBy(userAcademics.getModBy());
				userAcademicsValue.setModOn(Date.valueOf(LocalDate.now()));
				userAcademicsValue.setPassingYear(userAcademics.getPassingYear());
				userAcademicsValue.setUniversity(userAcademics.getUniversity());
				userAcademicsValue.setUser(userAcademics.getUser());
				userAcademicsValue.setValidity(userAcademics.getValidity());
			
				userAcademicsDao.updateUserAcademics(userAcademicsValue);
    	}else {
    		UserAcademics userAcademicsValue = new UserAcademics();
    		System.out.println("user Academics DTO to be sent to Dao is " + userAcademics.toString());
    		
    		userAcademicsValue.setIsValid(userAcademics.getIsValid());
    		userAcademicsValue.setHighestDegree(userAcademics.getHighestDegree());
    		userAcademicsValue.setModBy(userAcademics.getModBy());
    		userAcademicsValue.setModOn(userAcademics.getModOn());
    		userAcademicsValue.setPassingYear(userAcademics.getPassingYear());
    		userAcademicsValue.setUniversity(userAcademics.getUniversity());
    		userAcademicsValue.setUser(userAcademics.getUser());
    		userAcademicsValue.setValidity(userAcademics.getValidity());

    		userAcademicsDao.addUserAcademics(userAcademicsValue);
    	}
	return new ResponseEntity<UserAcademicsDTO>(userAcademics, HttpStatus.CREATED);
    }

	

    
    /*
     * (non-Javadoc)
     * @see com.easybusiness.usermanagement.services.user.UserService#LogoutUser(java.lang.String)
     * logging out user
     * this method logs out the user and set isActive field of user_login_details to N thus invalidates the login token 
     */
	@Override
	@CrossOrigin(origins = USER_HOST_SERVER)
    @RequestMapping(value = "getLogoutDetails/{loginToken}", method = RequestMethod.POST)
    @ResponseBody
	public UserLoginDetails LogoutUser(@PathVariable("loginToken") String loginToken) throws Exception {
		
			loginDao.updateLoginDetails(loginToken);
			
		return loginDao.getLoginDetailsByLoginToken(loginToken);
	}
	
	

	/*
	 * (non-Javadoc)
	 * @see com.easybusiness.usermanagement.services.user.UserService#getLoginDetails(java.lang.String, java.lang.String)
	 * login method for user
	 * this method takes username and password as param from the user and compares them with the existing username and
	 * password data in the user_details table, if this validation succeeds then the user can login and a login token 
	 * will be generated and stored in db in the table user_login_details with the fiels isActive having value Y
	 */
	@Override
	@CrossOrigin(origins = USER_HOST_SERVER)
    @RequestMapping(value = "login/{userName}/{password}", method = RequestMethod.POST)
    @ResponseBody
	public UserLoginDetails getLoginDetails(@PathVariable("userName") String userName,
												@PathVariable("password") String password) throws Exception {
		User userEntity = userDao.findByUserNameStream(userName).get(0);
		UserLoginDetails login = loginDao.getLoginDetailsByUserId(userName).get(0);
		/*String tokenId = login.getLoginToken();
		UserLoginDetails loginVerify = loginDao.getLoginDetailsByLoginToken(tokenId);*/
		UserLoginDetails loginSave = new UserLoginDetails();
		
		//getting password from user and comparing with original passoword
		String originalPassword = userEntity.getPassword();
		String hashedpass = Hashing.sha256()
				.hashString(password, StandardCharsets.UTF_8)
				.toString();
		
		/*SecureRandom random = new SecureRandom();
		long longToken = Math.abs(random.nextLong());
		String random1 = Long.toString(longToken, 16);
		String token1 = userEntity.getUserName().toUpperCase()+ random.hashCode();*/
		
		//generating login token for logging in
		 String SALTCHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
	        StringBuilder salt = new StringBuilder();
	        Random rnd = new Random();
	        while (salt.length() < 18) { // length of the random string.
	            int index = (int) (rnd.nextFloat() * SALTCHARS.length());
	            salt.append(SALTCHARS.charAt(index));
	        }
	        String saltStr = salt.toString();
	        System.out.println("length "+saltStr.length()+" token "+saltStr);
		
		/*DateTimeFormatter formatter = new DateTimeFormatterBuilder()
		        .appendPattern("MM").appendLiteral("")
		        .appendPattern("dd").appendLiteral("")
		        .appendPattern("yyyy").appendLiteral("")
		        .appendPattern("hh").appendLiteral("")
		        .appendPattern("mm").appendLiteral("")
		        .appendPattern("ss").appendLiteral("")
		        .appendPattern("a")
		        .toFormatter();
		String token = UUID.randomUUID().toString().toUpperCase() + LocalDateTime.now().format(formatter);*/
		
		if(login.getIsActive().equals("N") || login == null) {   //checking if user is already logged in or not
			if(hashedpass.equalsIgnoreCase(userEntity.getPassword())) {   //matching password
				
				LocalDate date = LocalDate.now();
				
				loginSave.setFirstName(userEntity.getFirstName());
				loginSave.setLastName(userEntity.getLastName());
				loginSave.setUserId(userEntity.getId());
				loginSave.setLastModifiedDate(Date.valueOf(date));
				loginSave.setCreateDate(Date.valueOf(date));
				loginSave.setIsActive("Y");
				loginSave.setUserName(userEntity.getUserName());
				loginSave.setCounter(login.getCounter()+1);
				loginSave.setLoginToken(saltStr);
				
				loginDao.saveLoginDetails(loginSave);
				System.out.println(Server.START_EVENT.length());
				System.out.println("inside login success");
			}else {
				System.out.println("inside login failed due to wrong password");
				return loginSave;
			}
		}else {
			System.out.println("inside login fail");
			System.out.println(login.getIsActive());
			return loginSave;
		}
		return loginSave;
	}

    /*private User prepareUserAcademicsEntity(UserAcademicsDTO userAcademicsDTO) {
	User userEntity = new User();
	userEntity.setAlternateEmail(userAcademicsDTO.getUser().getAlternateEmail());
	userEntity.setDateOfBirth(userAcademicsDTO.getUser().getDateOfBirth());
	Department dept = new Department();
	dept.setDeptName(userAcademicsDTO.getUser().getDepartment().getDeptName());
	dept.setId(userAcademicsDTO.getUser().getDepartment().getId());
	Organization org = new Organization();
	org.setId(userAcademicsDTO.getUser().getDepartment().getOrganization().getId());
	org.setOrgLocation(userAcademicsDTO.getUser().getDepartment().getOrganization().getOrgLocation());
	org.setOrgName(userAcademicsDTO.getUser().getDepartment().getOrganization().getOrgName());
	dept.setOrganization(org);
	userEntity.setDepartment(dept);
	Designation desg = new Designation();
	desg.setDesig(userAcademicsDTO.getUser().getDesignation().getDesig());
	desg.setId(userAcademicsDTO.getUser().getDesignation().getId());
	userEntity.setDesignation(desg);
	userEntity.setEmail(userAcademicsDTO.getUser().getEmail());
	userEntity.setEndDate(userAcademicsDTO.getUser().getEndDate());
	userEntity.setFirstName(userAcademicsDTO.getUser().getFirstName());
	userEntity.setFromDate(userAcademicsDTO.getUser().getFromDate());
	userEntity.setGender(userAcademicsDTO.getUser().getGender());
	userEntity.setIsEnabled(userAcademicsDTO.getUser().getIsEnabled());
	userEntity.setLastName(userAcademicsDTO.getUser().getLastName());
	userEntity.setMobile(userAcademicsDTO.getUser().getMobile());
	userEntity.setModifiedBy(userAcademicsDTO.getUser().getModifiedBy());
	userEntity.setModifiedOn(userAcademicsDTO.getUser().getModifiedOn());
	userEntity.setOrganization(org);
	userEntity.setPassword(userAcademicsDTO.getUser().getPassword().toString());
	userEntity.setTypeOfEmployment(userAcademicsDTO.getUser().getTypeOfEmployment());
	userEntity.setUserName(userAcademicsDTO.getUser().getUserName());
	userEntity.setId(userAcademicsDTO.getUser().getId());

	userEntity.setPermAddr(userAcademicsDTO.getUser().getPermAddr());
	userEntity.setState(userAcademicsDTO.getUser().getState());
	userEntity.setCity(userAcademicsDTO.getUser().getCity());
	userEntity.setCountry(userAcademicsDTO.getUser().getCountry());
	userEntity.setZip(userAcademicsDTO.getUser().getZip());
	userEntity.setFatherName(userAcademicsDTO.getUser().getFatherName());
	userEntity.setSpouseName(userAcademicsDTO.getUser().getSpouseName());
	userEntity.setPassport(userAcademicsDTO.getUser().getPassport());
	userEntity.setLocation(null == userAcademicsDTO.getUser().getLocation() ? null
		: prepareLocationEntity(userAcademicsDTO.getUser().getLocation()));
	userEntity.setUnitId(userAcademicsDTO.getUser().getUnitId());
	return userEntity;
    }*/

}
