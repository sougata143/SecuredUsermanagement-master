package com.easybusiness.usermanagement.entity.metadata;

import java.sql.Date;

import javax.annotation.Generated;
import javax.persistence.metamodel.SingularAttribute;
import javax.persistence.metamodel.StaticMetamodel;

import com.easybusiness.usermanagement.entity.PracticeMaster;
import com.easybusiness.usermanagement.entity.ProjectMaster;
import com.easybusiness.usermanagement.entity.User;
import com.easybusiness.usermanagement.entity.UserHierarchy;

@Generated(value = "org.hibernate.jpamodelgen.JPAMetaModelEntityProcessor")
@StaticMetamodel(UserHierarchy.class)
public abstract class UserHierarchy_ {
	
	public static volatile SingularAttribute<UserHierarchy, Long> HierarcyId;
	public static volatile SingularAttribute<UserHierarchy, User> user;
	public static volatile SingularAttribute<UserHierarchy, PracticeMaster> practiceMaster;
	public static volatile SingularAttribute<UserHierarchy, ProjectMaster> projectMaster;
	public static volatile SingularAttribute<UserHierarchy, User> priSupervisor;
	public static volatile SingularAttribute<UserHierarchy, User> hrManager;
	public static volatile SingularAttribute<UserHierarchy, Date> fromDate;
	public static volatile SingularAttribute<UserHierarchy, Date> toDate;
	public static volatile SingularAttribute<UserHierarchy, Date> prjAllocDate;
	public static volatile SingularAttribute<UserHierarchy, Date> prjReleaseDate;
	public static volatile SingularAttribute<UserHierarchy, String> status;
	public static volatile SingularAttribute<UserHierarchy, String> modBy;
	public static volatile SingularAttribute<UserHierarchy, Date> modOn;

}
