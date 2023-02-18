package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/field"
	"kratos-blog/pkg/util/entgo/mixin"
)

// Tag holds the schema definition for the Tag entity.
type Tag struct {
	ent.Schema
}

func (Tag) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{
			Table:     "tag",
			Charset:   "utf8mb4",
			Collation: "utf8mb4_bin",
		},
		entsql.WithComments(true),
	}
}

// Fields of the Tag.
func (Tag) Fields() []ent.Field {
	return []ent.Field{
		field.String("name").
			Comment("表情名").
			Unique().
			NotEmpty().
			Optional().
			Nillable(),

		field.String("color").
			Comment("颜色").
			Optional().
			Nillable(),

		field.String("thumbnail").
			Comment("缩略图").
			Optional().
			Nillable(),

		field.String("slug").
			Comment("链接别名").
			Optional().
			Nillable(),

		field.String("slug_name").
			Comment("链接别名").
			Optional().
			Nillable(),

		field.Uint32("post_count").
			Comment("博文计数").
			Optional().
			Nillable(),
	}
}

// Mixin of the Tag.
func (Tag) Mixin() []ent.Mixin {
	return []ent.Mixin{
		mixin.AutoIncrementId{},
		mixin.Time{},
	}
}

// Edges of the Tag.
func (Tag) Edges() []ent.Edge {
	return nil
}
