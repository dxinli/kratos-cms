// Code generated by ent, DO NOT EDIT.

package ent

import (
	"fmt"
	"strings"

	"entgo.io/ent/dialect/sql"
	"github.com/tx7do/kratos-blog/blog-backend/app/content/service/internal/data/ent/post"
)

// Post is the model entity for the Post schema.
type Post struct {
	config `json:"-"`
	// ID of the ent.
	// id
	ID uint32 `json:"id,omitempty"`
	// 创建时间
	CreateTime *int64 `json:"create_time,omitempty"`
	// 更新时间
	UpdateTime *int64 `json:"update_time,omitempty"`
	// 删除时间
	DeleteTime *int64 `json:"delete_time,omitempty"`
	// Title holds the value of the "title" field.
	Title *string `json:"title,omitempty"`
	// Slug holds the value of the "slug" field.
	Slug *string `json:"slug,omitempty"`
	// MetaKeywords holds the value of the "meta_keywords" field.
	MetaKeywords *string `json:"meta_keywords,omitempty"`
	// MetaDescription holds the value of the "meta_description" field.
	MetaDescription *string `json:"meta_description,omitempty"`
	// FullPath holds the value of the "full_path" field.
	FullPath *string `json:"full_path,omitempty"`
	// OriginalContent holds the value of the "original_content" field.
	OriginalContent *string `json:"original_content,omitempty"`
	// Content holds the value of the "content" field.
	Content *string `json:"content,omitempty"`
	// Summary holds the value of the "summary" field.
	Summary *string `json:"summary,omitempty"`
	// Thumbnail holds the value of the "thumbnail" field.
	Thumbnail *string `json:"thumbnail,omitempty"`
	// Password holds the value of the "password" field.
	Password *string `json:"password,omitempty"`
	// Template holds the value of the "template" field.
	Template *string `json:"template,omitempty"`
	// CommentCount holds the value of the "comment_count" field.
	CommentCount *int32 `json:"comment_count,omitempty"`
	// Visits holds the value of the "visits" field.
	Visits *int32 `json:"visits,omitempty"`
	// Likes holds the value of the "likes" field.
	Likes *int32 `json:"likes,omitempty"`
	// WordCount holds the value of the "word_count" field.
	WordCount *int32 `json:"word_count,omitempty"`
	// TopPriority holds the value of the "top_priority" field.
	TopPriority *int32 `json:"top_priority,omitempty"`
	// Status holds the value of the "status" field.
	Status *int32 `json:"status,omitempty"`
	// EditorType holds the value of the "editor_type" field.
	EditorType *int32 `json:"editor_type,omitempty"`
	// 编辑时间
	EditTime *int64 `json:"edit_time,omitempty"`
	// DisallowComment holds the value of the "disallow_comment" field.
	DisallowComment *bool `json:"disallow_comment,omitempty"`
	// InProgress holds the value of the "in_progress" field.
	InProgress *bool `json:"in_progress,omitempty"`
}

// scanValues returns the types for scanning values from sql.Rows.
func (*Post) scanValues(columns []string) ([]any, error) {
	values := make([]any, len(columns))
	for i := range columns {
		switch columns[i] {
		case post.FieldDisallowComment, post.FieldInProgress:
			values[i] = new(sql.NullBool)
		case post.FieldID, post.FieldCreateTime, post.FieldUpdateTime, post.FieldDeleteTime, post.FieldCommentCount, post.FieldVisits, post.FieldLikes, post.FieldWordCount, post.FieldTopPriority, post.FieldStatus, post.FieldEditorType, post.FieldEditTime:
			values[i] = new(sql.NullInt64)
		case post.FieldTitle, post.FieldSlug, post.FieldMetaKeywords, post.FieldMetaDescription, post.FieldFullPath, post.FieldOriginalContent, post.FieldContent, post.FieldSummary, post.FieldThumbnail, post.FieldPassword, post.FieldTemplate:
			values[i] = new(sql.NullString)
		default:
			return nil, fmt.Errorf("unexpected column %q for type Post", columns[i])
		}
	}
	return values, nil
}

// assignValues assigns the values that were returned from sql.Rows (after scanning)
// to the Post fields.
func (po *Post) assignValues(columns []string, values []any) error {
	if m, n := len(values), len(columns); m < n {
		return fmt.Errorf("mismatch number of scan values: %d != %d", m, n)
	}
	for i := range columns {
		switch columns[i] {
		case post.FieldID:
			value, ok := values[i].(*sql.NullInt64)
			if !ok {
				return fmt.Errorf("unexpected type %T for field id", value)
			}
			po.ID = uint32(value.Int64)
		case post.FieldCreateTime:
			if value, ok := values[i].(*sql.NullInt64); !ok {
				return fmt.Errorf("unexpected type %T for field create_time", values[i])
			} else if value.Valid {
				po.CreateTime = new(int64)
				*po.CreateTime = value.Int64
			}
		case post.FieldUpdateTime:
			if value, ok := values[i].(*sql.NullInt64); !ok {
				return fmt.Errorf("unexpected type %T for field update_time", values[i])
			} else if value.Valid {
				po.UpdateTime = new(int64)
				*po.UpdateTime = value.Int64
			}
		case post.FieldDeleteTime:
			if value, ok := values[i].(*sql.NullInt64); !ok {
				return fmt.Errorf("unexpected type %T for field delete_time", values[i])
			} else if value.Valid {
				po.DeleteTime = new(int64)
				*po.DeleteTime = value.Int64
			}
		case post.FieldTitle:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field title", values[i])
			} else if value.Valid {
				po.Title = new(string)
				*po.Title = value.String
			}
		case post.FieldSlug:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field slug", values[i])
			} else if value.Valid {
				po.Slug = new(string)
				*po.Slug = value.String
			}
		case post.FieldMetaKeywords:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field meta_keywords", values[i])
			} else if value.Valid {
				po.MetaKeywords = new(string)
				*po.MetaKeywords = value.String
			}
		case post.FieldMetaDescription:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field meta_description", values[i])
			} else if value.Valid {
				po.MetaDescription = new(string)
				*po.MetaDescription = value.String
			}
		case post.FieldFullPath:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field full_path", values[i])
			} else if value.Valid {
				po.FullPath = new(string)
				*po.FullPath = value.String
			}
		case post.FieldOriginalContent:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field original_content", values[i])
			} else if value.Valid {
				po.OriginalContent = new(string)
				*po.OriginalContent = value.String
			}
		case post.FieldContent:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field content", values[i])
			} else if value.Valid {
				po.Content = new(string)
				*po.Content = value.String
			}
		case post.FieldSummary:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field summary", values[i])
			} else if value.Valid {
				po.Summary = new(string)
				*po.Summary = value.String
			}
		case post.FieldThumbnail:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field thumbnail", values[i])
			} else if value.Valid {
				po.Thumbnail = new(string)
				*po.Thumbnail = value.String
			}
		case post.FieldPassword:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field password", values[i])
			} else if value.Valid {
				po.Password = new(string)
				*po.Password = value.String
			}
		case post.FieldTemplate:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field template", values[i])
			} else if value.Valid {
				po.Template = new(string)
				*po.Template = value.String
			}
		case post.FieldCommentCount:
			if value, ok := values[i].(*sql.NullInt64); !ok {
				return fmt.Errorf("unexpected type %T for field comment_count", values[i])
			} else if value.Valid {
				po.CommentCount = new(int32)
				*po.CommentCount = int32(value.Int64)
			}
		case post.FieldVisits:
			if value, ok := values[i].(*sql.NullInt64); !ok {
				return fmt.Errorf("unexpected type %T for field visits", values[i])
			} else if value.Valid {
				po.Visits = new(int32)
				*po.Visits = int32(value.Int64)
			}
		case post.FieldLikes:
			if value, ok := values[i].(*sql.NullInt64); !ok {
				return fmt.Errorf("unexpected type %T for field likes", values[i])
			} else if value.Valid {
				po.Likes = new(int32)
				*po.Likes = int32(value.Int64)
			}
		case post.FieldWordCount:
			if value, ok := values[i].(*sql.NullInt64); !ok {
				return fmt.Errorf("unexpected type %T for field word_count", values[i])
			} else if value.Valid {
				po.WordCount = new(int32)
				*po.WordCount = int32(value.Int64)
			}
		case post.FieldTopPriority:
			if value, ok := values[i].(*sql.NullInt64); !ok {
				return fmt.Errorf("unexpected type %T for field top_priority", values[i])
			} else if value.Valid {
				po.TopPriority = new(int32)
				*po.TopPriority = int32(value.Int64)
			}
		case post.FieldStatus:
			if value, ok := values[i].(*sql.NullInt64); !ok {
				return fmt.Errorf("unexpected type %T for field status", values[i])
			} else if value.Valid {
				po.Status = new(int32)
				*po.Status = int32(value.Int64)
			}
		case post.FieldEditorType:
			if value, ok := values[i].(*sql.NullInt64); !ok {
				return fmt.Errorf("unexpected type %T for field editor_type", values[i])
			} else if value.Valid {
				po.EditorType = new(int32)
				*po.EditorType = int32(value.Int64)
			}
		case post.FieldEditTime:
			if value, ok := values[i].(*sql.NullInt64); !ok {
				return fmt.Errorf("unexpected type %T for field edit_time", values[i])
			} else if value.Valid {
				po.EditTime = new(int64)
				*po.EditTime = value.Int64
			}
		case post.FieldDisallowComment:
			if value, ok := values[i].(*sql.NullBool); !ok {
				return fmt.Errorf("unexpected type %T for field disallow_comment", values[i])
			} else if value.Valid {
				po.DisallowComment = new(bool)
				*po.DisallowComment = value.Bool
			}
		case post.FieldInProgress:
			if value, ok := values[i].(*sql.NullBool); !ok {
				return fmt.Errorf("unexpected type %T for field in_progress", values[i])
			} else if value.Valid {
				po.InProgress = new(bool)
				*po.InProgress = value.Bool
			}
		}
	}
	return nil
}

// Update returns a builder for updating this Post.
// Note that you need to call Post.Unwrap() before calling this method if this Post
// was returned from a transaction, and the transaction was committed or rolled back.
func (po *Post) Update() *PostUpdateOne {
	return NewPostClient(po.config).UpdateOne(po)
}

// Unwrap unwraps the Post entity that was returned from a transaction after it was closed,
// so that all future queries will be executed through the driver which created the transaction.
func (po *Post) Unwrap() *Post {
	_tx, ok := po.config.driver.(*txDriver)
	if !ok {
		panic("ent: Post is not a transactional entity")
	}
	po.config.driver = _tx.drv
	return po
}

// String implements the fmt.Stringer.
func (po *Post) String() string {
	var builder strings.Builder
	builder.WriteString("Post(")
	builder.WriteString(fmt.Sprintf("id=%v, ", po.ID))
	if v := po.CreateTime; v != nil {
		builder.WriteString("create_time=")
		builder.WriteString(fmt.Sprintf("%v", *v))
	}
	builder.WriteString(", ")
	if v := po.UpdateTime; v != nil {
		builder.WriteString("update_time=")
		builder.WriteString(fmt.Sprintf("%v", *v))
	}
	builder.WriteString(", ")
	if v := po.DeleteTime; v != nil {
		builder.WriteString("delete_time=")
		builder.WriteString(fmt.Sprintf("%v", *v))
	}
	builder.WriteString(", ")
	if v := po.Title; v != nil {
		builder.WriteString("title=")
		builder.WriteString(*v)
	}
	builder.WriteString(", ")
	if v := po.Slug; v != nil {
		builder.WriteString("slug=")
		builder.WriteString(*v)
	}
	builder.WriteString(", ")
	if v := po.MetaKeywords; v != nil {
		builder.WriteString("meta_keywords=")
		builder.WriteString(*v)
	}
	builder.WriteString(", ")
	if v := po.MetaDescription; v != nil {
		builder.WriteString("meta_description=")
		builder.WriteString(*v)
	}
	builder.WriteString(", ")
	if v := po.FullPath; v != nil {
		builder.WriteString("full_path=")
		builder.WriteString(*v)
	}
	builder.WriteString(", ")
	if v := po.OriginalContent; v != nil {
		builder.WriteString("original_content=")
		builder.WriteString(*v)
	}
	builder.WriteString(", ")
	if v := po.Content; v != nil {
		builder.WriteString("content=")
		builder.WriteString(*v)
	}
	builder.WriteString(", ")
	if v := po.Summary; v != nil {
		builder.WriteString("summary=")
		builder.WriteString(*v)
	}
	builder.WriteString(", ")
	if v := po.Thumbnail; v != nil {
		builder.WriteString("thumbnail=")
		builder.WriteString(*v)
	}
	builder.WriteString(", ")
	if v := po.Password; v != nil {
		builder.WriteString("password=")
		builder.WriteString(*v)
	}
	builder.WriteString(", ")
	if v := po.Template; v != nil {
		builder.WriteString("template=")
		builder.WriteString(*v)
	}
	builder.WriteString(", ")
	if v := po.CommentCount; v != nil {
		builder.WriteString("comment_count=")
		builder.WriteString(fmt.Sprintf("%v", *v))
	}
	builder.WriteString(", ")
	if v := po.Visits; v != nil {
		builder.WriteString("visits=")
		builder.WriteString(fmt.Sprintf("%v", *v))
	}
	builder.WriteString(", ")
	if v := po.Likes; v != nil {
		builder.WriteString("likes=")
		builder.WriteString(fmt.Sprintf("%v", *v))
	}
	builder.WriteString(", ")
	if v := po.WordCount; v != nil {
		builder.WriteString("word_count=")
		builder.WriteString(fmt.Sprintf("%v", *v))
	}
	builder.WriteString(", ")
	if v := po.TopPriority; v != nil {
		builder.WriteString("top_priority=")
		builder.WriteString(fmt.Sprintf("%v", *v))
	}
	builder.WriteString(", ")
	if v := po.Status; v != nil {
		builder.WriteString("status=")
		builder.WriteString(fmt.Sprintf("%v", *v))
	}
	builder.WriteString(", ")
	if v := po.EditorType; v != nil {
		builder.WriteString("editor_type=")
		builder.WriteString(fmt.Sprintf("%v", *v))
	}
	builder.WriteString(", ")
	if v := po.EditTime; v != nil {
		builder.WriteString("edit_time=")
		builder.WriteString(fmt.Sprintf("%v", *v))
	}
	builder.WriteString(", ")
	if v := po.DisallowComment; v != nil {
		builder.WriteString("disallow_comment=")
		builder.WriteString(fmt.Sprintf("%v", *v))
	}
	builder.WriteString(", ")
	if v := po.InProgress; v != nil {
		builder.WriteString("in_progress=")
		builder.WriteString(fmt.Sprintf("%v", *v))
	}
	builder.WriteByte(')')
	return builder.String()
}

// Posts is a parsable slice of Post.
type Posts []*Post

func (po Posts) config(cfg config) {
	for _i := range po {
		po[_i].config = cfg
	}
}
